/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "threads_priv.h"
#include <arch/aarch64/arch/threads.h>
#include <stdio.h>
#include <string.h>
#include <mm/mm.h>

#define EXCEPTION_STACK_SIZE (1 << 14)
#define LAZY_MAP_CAP_SIZE (BASE_PAGE_SIZE * 128)
static char stack_first[EXCEPTION_STACK_SIZE];

static struct paging_state current;
errval_t allocate_new_pagetable(struct paging_state * st, capaddr_t slot, 
                  uint64_t offset, uint64_t pte_ct, enum objtype type, struct page_table * parent); 
void pf_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs);
void page_fault_handler(void *faulting_address);

static errval_t paging_addr_is_already_mapped(struct paging_state *st, lvaddr_t *vaddr);

/**
 * @brief allocates a new page table for the given paging state with the given type
 *
 * @param[in]  st    paging state to allocate the page table for (required for slot allcator)
 * @param[in]  type  the type of the page table to create
 * @param[out] ret   returns the capref to the newly allocated page table
 *
 * @returns error value indicating success or failure
 *   - @retval SYS_ERR_OK if the allocation was successfull
 *   - @retval LIB_ERR_SLOT_ALLOC if there couldn't be a slot allocated for the new page table
 *   - @retval LIB_ERR_VNODE_CREATE if the page table couldn't be created
 */
static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret)
{
    errval_t err;

    assert(type == ObjType_VNode_AARCH64_l0 || type == ObjType_VNode_AARCH64_l1
           || type == ObjType_VNode_AARCH64_l2 || type == ObjType_VNode_AARCH64_l3);

    // try to get a slot from the slot allocator to hold the new page table
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC); 
    }


    // create the vnode in the supplied slot
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state *st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


/**
 * @brief Initializes the paging state struct for the current process.
 *
 * @param[in] st           The paging state to be initialized.
 * @param[in] start_vaddr  Starting virtual address to be managed.
 * @param[in] root         Capability for the root-level page table.
 * @param[in] ca           Slot allocator instance to be used.
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr, struct capref root,
                           struct slot_allocator *ca)
{

    printf("Invoking paging_init_state\n");

    st->current_vaddr = start_vaddr;
    st->start_vaddr = start_vaddr;
    st->slot_alloc = ca;

    static char initial_slab_buffer[100 * 20480];
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));
    
    st->root = slab_alloc(&st->slab_allocator); 
     if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL; 
    }

    // Initialize the root page table fields
    st->root->parent = NULL;            // Root has no parent
    st->root->mapping = root;           // Root mapping cap reference
    st->root->cap = root;               // Root capability
    st->root->self = root;
    st->root->offset = 0;               // Offset is 0 for root page table
    st->root->numBytes = 0;             // Initialize to 0, will track the size of allocations later
    for (int i = 0; i < NUM_PT_SLOTS; i++) {
        st->root->children[i] = NULL;   // No children initially
    }

    // Initialize the region list to NULL (no regions initially)
    st->region_list = NULL;

    return SYS_ERR_OK;  
    
}

void pf_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs)
{ 
    (void)subtype; 
    (void)regs;
    if (type == EXCEPT_PAGEFAULT) {
        printf("Page fault occurred at address: %p\n", addr);
        page_fault_handler(addr);  // No need to assign to errval_t since it returns void
    } else {
        USER_PANIC(": unhandled exception (type %d) on %p\n", type, addr);
    }
}


/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    printf("Invoke the function paging_init\n");

    // TODO (M1): Call paging_init_state for &current

    // TODO (M2): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.

    /**
    (uint64_t)1)<<46: starting virtual address for the domain's memory space
    Lower part of the virtual address space -> kernel operations, higher part for user-space processes
    We here map the the upper part of the virtual address space
    */
    errval_t err = paging_init_state(&current, ((uint64_t)1)<<46, cap_vroot, get_default_slot_allocator());   
    if (err_is_fail(err)) {
        return err;
    }
    set_current_paging_state(&current);

    // Set up page fault handler for this thread
    void *stack_top = stack_first + EXCEPTION_STACK_SIZE;
    stack_top = (void *)ALIGNED_STACK_TOP(stack_top);
    
    err = thread_set_exception_handler(pf_handler, NULL, stack_first, stack_top,
                                   NULL, NULL);
    return SYS_ERR_OK;
}


/**
 * @brief frees up the resources allocate in the foreign paging state
 *
 * @param[in] st   the foreign paging state to be freed
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 *
 * Note: this function will free up the resources of *the current* paging state
 * that were used to construct the foreign paging state. There should be no effect
 * on the paging state of the foreign process.
 */
errval_t paging_free_state_foreign(struct paging_state *st)
{
    (void)st;
    // TODO: implement me
    return SYS_ERR_OK;
}


/**
 * @brief Initializes the paging functionality for the calling thread
 *
 * @param[in] t   the tread to initialize the paging state for.
 *
 * This function prepares the thread to handing its own page faults
 */
errval_t paging_init_onthread(struct thread *t)
{
    // make compiler happy about unused parameters
    (void)t;

    // TODO (M2):
    //   - setup exception handler for thread `t'.
    return LIB_ERR_NOT_IMPLEMENTED;
}



/**
 * @brief Find a free region of virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    /**
     * TODO(M1):
     *    - use a linear allocation scheme. (think about what allocation sizes are valid)
     *
     * TODO(M2): Implement this function
     *   - Find a region of free virtual address space that is large enough to
     *     accomodate a buffer of size `bytes`.
     */
    
    printf("Invoke the paging_alloc function\n");
    size_t aligned_bytes = ROUND_UP(bytes, alignment);

    genvaddr_t vaddr = st->current_vaddr;

    // Reserve the virtual address space by incrementing current_vaddr
    st->current_vaddr += aligned_bytes;

    // Track the lazily allocated region in the paging_state's region list
    struct paging_region *new_region = slab_alloc(&st->slab_allocator);
    if (new_region == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Initialize the lazily allocated region
    new_region->base_addr = vaddr;         // Start of the reserved virtual address range
    new_region->region_size = aligned_bytes; // Size of the allocated virtual memory region
    new_region->flags = VREGION_FLAGS_READ_WRITE; // Default permissions (adjust if needed)
    new_region->type = PAGING_REGION_LAZY;  // Mark this region as lazily allocated
    new_region->next = st->region_list;     // Add it to the head of the region list
    st->region_list = new_region;           // Update the region list in the paging state

    // Return the base virtual address of the reserved region
    *buf = (void *)vaddr;

    printf("Reserved virtual address range [%p - %p] as lazily allocated\n",
           (void *)vaddr, (void *)(vaddr + aligned_bytes));

    return SYS_ERR_OK;
}




/**
 * @brief maps a frame at a free virtual address region and returns its address
 * mapping a physical memory frame (represented by frame) into a virtual address space
 * @param[in]  st      paging state of the address space to create the mapping in
 * @param[out] buf     returns the virtual address of the mapped frame
 * @param[in]  bytes   the amount of bytes to be mapped
 * @param[in]  frame   frame capability of backing memory to be mapped
 * @param[in]  offset  offset into the frame capability to be mapped
 * @param[in]  flags   mapping flags
 *
 * @return SYS_ERR_OK on sucecss, LIB_ERR_* on failure.
 */
errval_t paging_map_frame_attr_offset(struct paging_state *st, void **buf, size_t bytes,
                                      struct capref frame, size_t offset, int flags)
{   
     // make compiler happy about unused parameters
    (void)st;
    (void)buf;
    (void)bytes;
    (void)frame;
    (void)offset;
    (void)flags;
    // TODO(M1):
    //  - decide on which virtual address to map the frame at
    //  - map the frame assuming all mappings will fit into one leaf page table (L3)  (fail otherwise)
    //  - return the virtual address of the created mapping
    //
    // TODO(M2):
    // - General case: you will need to handle mappings spanning multiple leaf page tables.
    // - Find and allocate free region of virtual address space of at least bytes in size.
    // - Map the user provided frame at the free virtual address
    // - return the virtual address in the buf parameter
    //
    // Hint:
    //  - think about what mapping configurations are actually possible

    // Lazy
    // errval_t err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    // if (err_is_fail(err)) {
    //     return err_push(err, SYS_ERR_ID_SPACE_EXHAUSTED);
    // }

    // printf("Reserved virtual address range [%p - %p] for lazy allocation\n",
    //        (void *)(*buf), (void *)((genvaddr_t)(*buf) + bytes));

    paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    
    // This eager allocation works
    genvaddr_t vaddr = (genvaddr_t)*buf;
    errval_t err = paging_map_fixed_attr_offset(st, vaddr, frame, bytes, offset, flags);
    if (err_is_fail(err)) {
        printf("vnode_map failed: %s\n", err_getstring(err));
        return -1;
    }


    return SYS_ERR_OK;
}

errval_t allocate_new_pagetable(struct paging_state * st, capaddr_t slot, 
                  uint64_t offset, uint64_t pte_ct, enum objtype type, struct page_table * parent) {
    errval_t err;

    parent->children[slot] = (struct page_table*)slab_alloc(&(st->slab_allocator));
    
    struct capref mapping;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc(st, type, &(parent->children[slot]->self));

    
    err = vnode_map(parent->self, parent->children[slot]->self, 
                    slot, VREGION_FLAGS_READ_WRITE, offset, pte_ct, mapping);
    if (err_is_fail(err)) {
        printf("     vnode_map failed mapping: %s\n", err_getstring(err));
        return -1;
    }

    for (int i = 0; i < NUM_PT_SLOTS; i++) {
        parent->children[slot]->children[i] = NULL;
    }

    return SYS_ERR_OK;
}

/**
 * @brief maps a frame at a user-provided virtual address region
 *
 * @param[in] st      paging state of the address space to create the mapping in
 * @param[in] vaddr   provided virtual address to map the frame at
 * @param[in] frame   frame capability of backing memory to be mapped
 * @param[in] bytes   the amount of bytes to be mapped
 * @param[in] offset  offset into the frame capability to be mapped
 * @param[in] flags   mapping flags
 *
 * @return SYS_ERR_OK on success, LIB_ERR_* on failure
 *
 * The region at which the frame is requested to be mapped must be free (i.e., hasn't been
 * allocated), otherwise the mapping request shoud fail.
 */
errval_t paging_map_fixed_attr_offset(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                                      size_t bytes, size_t offset, int flags)
{
    errval_t result;
    int pages_mapped;

    // Determine the total number of pages to map based on the provided bytes
    int total_pages = ROUND_UP(bytes, BASE_PAGE_SIZE) / BASE_PAGE_SIZE;
    int remaining_pages = total_pages;

    // Perform the mapping in chunks that fit within an L3 page table
    for (int i = 0; remaining_pages > 0; i++) {
        // Calculate page table indices for the current virtual address
        int l0_idx = VMSAv8_64_L0_INDEX(vaddr);
        int l1_idx = VMSAv8_64_L1_INDEX(vaddr);
        int l2_idx = VMSAv8_64_L2_INDEX(vaddr);
        int l3_idx = VMSAv8_64_L3_INDEX(vaddr);

        // Allocate and initialize a new L1 page table if necessary
        if (st->root->children[l0_idx] == NULL) {
            result = allocate_new_pagetable(st, l0_idx, offset, 1, ObjType_VNode_AARCH64_l1, st->root);
            if (err_is_fail(result)) {
                printf("Error allocating L1 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        // Allocate and initialize a new L2 page table if necessary
        if (st->root->children[l0_idx]->children[l1_idx] == NULL) {
            result = allocate_new_pagetable(st, l1_idx, offset, 1, ObjType_VNode_AARCH64_l2, 
                                            st->root->children[l0_idx]);
            if (err_is_fail(result)) {
                printf("Error allocating L2 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        // Allocate and initialize a new L3 page table if necessary
        if (st->root->children[l0_idx]->children[l1_idx]->children[l2_idx] == NULL) {
            result = allocate_new_pagetable(st, l2_idx, offset, 1, ObjType_VNode_AARCH64_l3, 
                                            st->root->children[l0_idx]->children[l1_idx]);
            if (err_is_fail(result)) {
                printf("Error allocating L3 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        // Allocate a slot for mapping pages within the L3 page table
        //struct capref map_slot;
        // struct slot_prealloc *ca = (struct slot_prealloc *)st->slot_alloc;
        // result = slot_prealloc_refill(ca);
        // result = slot_prealloc_alloc(ca, &map_slot);
        // if (err_is_fail(result)) {
        //     return err_push(result, LIB_ERR_SLOT_ALLOC);
        // }

        struct capref map_slot;
        result = st->slot_alloc->alloc(st->slot_alloc, &map_slot);
        if (err_is_fail(result)) {
            return err_push(result, LIB_ERR_SLOT_ALLOC);
        }

        // Map the maximum number of pages that can fit into the L3 page table
        pages_mapped = MIN((int)(NUM_PT_SLOTS - l3_idx), remaining_pages);
        result = vnode_map(st->root->children[l0_idx]->children[l1_idx]->children[l2_idx]->self, 
                           frame, l3_idx, flags, offset + (BASE_PAGE_SIZE * (total_pages - remaining_pages)), 
                           pages_mapped, map_slot);
        if (err_is_fail(result)) {
            printf("vnode_map failed during leaf node mapping: %s\n", err_getstring(result));
            return result;
        }

        // Mark remaining slots in this L3 page table as unused
        vaddr += BASE_PAGE_SIZE;
        for (int j = VMSAv8_64_L3_INDEX(vaddr); j < NUM_PT_SLOTS; j++) {
            st->root->children[l0_idx]->children[l1_idx]->children[l2_idx]->children[l3_idx] = (void*)1;
            vaddr += BASE_PAGE_SIZE;
        }

        // Update the remaining pages count
        remaining_pages -= pages_mapped;

        // Check and refill the slab allocator if necessary
        result = slab_refill_check(&(st->slab_allocator));
        if (err_is_fail(result)) {
            printf("Slab allocation error: %s\n", err_getstring(result));
            return LIB_ERR_SLAB_REFILL;
        }
    }

    return SYS_ERR_OK;
}

/**
 * @brief Check if the given virtual address is already mapped.
 *
 * @param[in] st      Paging state for the current address space
 * @param[in] vaddr   Virtual address to check
 *
 * @return true if the address is already mapped, false otherwise.
 */
static errval_t paging_addr_is_already_mapped(struct paging_state *st, lvaddr_t *vaddr)
{
    errval_t err;
    printf("Invoke the  paging_addr_is_already_mapped function\n");
    // Lock the paging mutex to ensure safe concurrent access
    thread_mutex_lock(&st->paging_mutex);

    // Dereference the vaddr pointer to get the actual address value
    lvaddr_t address = *vaddr;

    // Use the provided index functions to get the index at each page table level
    uint64_t l0_idx = VMSAv8_64_L0_INDEX(address);
    uint64_t l1_idx = VMSAv8_64_L1_INDEX(address);
    uint64_t l2_idx = VMSAv8_64_L2_INDEX(address);
    uint64_t l3_idx = VMSAv8_64_L3_INDEX(address);

    // Start traversing from the root (L0 page table)
    struct page_table *l0_table = st->root;

    // Check if the L0 page table entry exists
    if (l0_table->children[l0_idx] == NULL) {
        // L0 entry is not present, the address is not mapped
        err = LIB_ERR_VSPACE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }

    // Traverse to the L1 page table
    struct page_table *l1_table = l0_table->children[l0_idx];
    if (l1_table->children[l1_idx] == NULL) {
        // L1 entry is not present, the address is not mapped
        err = LIB_ERR_VSPACE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }

    // Traverse to the L2 page table
    struct page_table *l2_table = l1_table->children[l1_idx];
    if (l2_table->children[l2_idx] == NULL) {
        // L2 entry is not present, the address is not mapped
        err = LIB_ERR_VSPACE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }

    // Traverse to the L3 page table (the leaf page table)
    struct page_table *l3_table = l2_table->children[l2_idx];
    if (l3_table == NULL || capref_is_null(l3_table->self)) {
        // L3 entry is not present or no valid mapping exists
        err = LIB_ERR_VSPACE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }

    // Check if the specific entry in the L3 page table is present
    if (l3_table->children[l3_idx] == NULL) {
        // L3 entry is not present, the address is not mapped
        err = LIB_ERR_VSPACE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }
     printf("Finish the  paging_addr_is_already_mapped function\n");
    // If all levels have valid entries, the address is mapped
    err = SYS_ERR_OK;

out:
    thread_mutex_unlock(&st->paging_mutex);
    return err;
}



void page_fault_handler(void *faulting_address)
{
    printf("Page fault occurred at address: %p\n", (void*)faulting_address);

    struct paging_state *st = get_current_paging_state();

    // Convert the faulting address to `lvaddr_t`
    lvaddr_t aligned_faulting_address = (lvaddr_t)faulting_address & ~(BASE_PAGE_SIZE - 1); // Align address

    // Check if the address is already mapped
    printf("Checking whether the address is already mapped or not\n");
    errval_t err = paging_addr_is_already_mapped(st, &aligned_faulting_address);
    if (err == SYS_ERR_OK) {
        printf("Address is already mapped, returning from the handler\n");
        return;
    }

    // The address is not mapped, continue with the page fault handling
    printf("Address not mapped, proceeding with page fault handling\n");

    // Find the region where the page fault occurred
    struct paging_region *region = st->region_list;
    while (region != NULL) {
        if ((genvaddr_t)faulting_address >= region->base_addr &&
            (genvaddr_t)faulting_address < region->base_addr + region->region_size) {
            break;
        }   
        region = region->next;
    }

    // No region found, handle the error
    if (region == NULL) { 
        USER_PANIC("Page fault occurred at an unmapped region: %p\n", faulting_address);
        return;
    }

    // Check if the region is lazily allocated
    if (region->type != PAGING_REGION_LAZY) {
        USER_PANIC("Page fault outside lazily allocated region: %p\n", faulting_address);
        return;
    }

    // Allocate and map the frame for this lazily allocated region
    printf("Allocating and mapping frame for lazily allocated region\n");

    struct capref frame;
    err = frame_alloc(&frame, region->region_size, NULL); // Allocate a frame
    if (err_is_fail(err)) {
        USER_PANIC("Frame allocation failed: %s\n", err_getstring(err));
        return;
    }

    // Map the frame to the virtual address space
    err = paging_map_fixed_attr_offset(st, aligned_faulting_address, frame, region->region_size, 0, region->flags);
    if (err_is_fail(err)) {
        USER_PANIC("Frame mapping failed: %s\n", err_getstring(err));
        return;
    }

    // Refill slab allocator if necessary
    slab_refill_check(&(st->slab_allocator));

    printf("Successfully handled page fault for lazy allocation at %p\n", faulting_address);
}



/**
 * @brief Unmaps the region starting at the supplied pointer.
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] region  starting address of the region to unmap
 *
 * @return SYS_ERR_OK on success, or error code indicating the kind of failure
 *
 * The supplied `region` must be the start of a previously mapped frame.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    struct paging_region *prev = NULL;
    struct paging_region *curr = st->region_list;

    // Step 1: Find the region associated with the address
    while (curr != NULL) {
        if (curr->base_addr == (genvaddr_t)region) {
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) {
        return LIB_ERR_VSPACE_VREGION_NOT_FOUND; // Region not found
    }

    // Step 2: Unmap all pages in the region
    genvaddr_t vaddr = curr->base_addr;
    size_t remaining_bytes = curr->region_size;

    while (remaining_bytes > 0) {
        // Get the L3 page table index for the virtual address
        int l0_idx = VMSAv8_64_L0_INDEX(vaddr);
        int l1_idx = VMSAv8_64_L1_INDEX(vaddr);
        int l2_idx = VMSAv8_64_L2_INDEX(vaddr);
        int l3_idx = VMSAv8_64_L3_INDEX(vaddr);

        // Check if the page table exists, if not skip
        if (st->root->children[l0_idx] == NULL ||
            st->root->children[l0_idx]->children[l1_idx] == NULL ||
            st->root->children[l0_idx]->children[l1_idx]->children[l2_idx] == NULL) {
            return LIB_ERR_VSPACE_VREGION_NOT_FOUND;
        }

        struct page_table *l3_table = st->root->children[l0_idx]->children[l1_idx]->children[l2_idx];

        if (l3_table->children[l3_idx] == NULL) {
            return LIB_ERR_VSPACE_VREGION_NOT_FOUND;
        }

       // Step 3: Perform unmapping for the current page
        struct capref mapping_cap = l3_table->children[l3_idx]->mapping; // Correct capref

        errval_t err = vnode_unmap(l3_table->self, mapping_cap);  // Use the mapping capref
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_VNODE_UNMAP);
        }

        // Free the mapping
        slab_free(&st->slab_allocator, l3_table->children[l3_idx]);
        l3_table->children[l3_idx] = NULL;

        // Move to the next page
        vaddr += BASE_PAGE_SIZE;
        remaining_bytes -= BASE_PAGE_SIZE;
    }

    // Step 4: Free the region and update the region list
    if (prev == NULL) {
        // This was the first region in the list
        st->region_list = curr->next;
    } else {
        // Remove from the middle of the list
        prev->next = curr->next;
    }

    // Free the region structure
    slab_free(&st->slab_allocator, curr);

    return SYS_ERR_OK;
}