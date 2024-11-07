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
    debug_printf("invoke pt_alloc\n");

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

__attribute__((unused)) errval_t pt_alloc_l1(struct paging_state *st, struct capref *ret)
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
 * @brief initializes the paging state struct for a foreign process when spawning a new one
 *
 * @param[in] st           the paging state to be initialized
 * @param[in] start_vaddr  start virtual address to be managed
 * @param[in] root         capability to the root leve page table
 * @param[in] ca           the slot allocator instance to be used
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 */
/**
 * @brief Initializes the paging state struct for a foreign (child) process.
 *
 * @param[in] st           The paging state to be initialized.
 * @param[in] start_vaddr  Starting virtual address to be managed.
 * @param[in] root         Capability for the root-level page table in the child’s CSpace.
 * @param[in] ca           Slot allocator instance to be used.
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref root, struct slot_allocator *ca)
{
    // Initialize basic fields for the paging state struct
    st->current_vaddr = start_vaddr;
    st->start_vaddr = start_vaddr;
    st->slot_alloc = ca;

    // Initialize the slab allocator for paging regions
    static char slab_buffer[100 * 20480];  // Adjust size as necessary
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, slab_buffer, sizeof(slab_buffer));

    // Allocate memory for the root page table using the slab allocator
    st->root = slab_alloc(&st->slab_allocator);
    if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Set up the root page table properties
    st->root->parent = NULL;          // The root has no parent
    st->root->cap = root;             // Root capability (from child’s CSpace)
    st->root->self = root;            // Self reference to root cap in foreign space
    st->root->mapping = root;         // Mapping cap reference
    st->root->offset = 0;             // Offset is zero for root
    st->root->numBytes = 0;           // Initialize size tracking to zero
    printf("Root slot %s\n", st->root->cap.slot);

    // Initialize all child page table entries to NULL initially
    for (int i = 0; i < NUM_PT_SLOTS; i++) {
        st->root->children[i] = NULL;
    }

    // Set the region and free lists to NULL initially
    st->mapped_list = NULL;
    st->region_list = NULL;
    st->free_list = NULL;

    return SYS_ERR_OK;
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
        printf("subtype: %p\n", subtype);
        page_fault_handler(addr);  
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
    
    // printf("Invoke the paging_alloc function\n");
    size_t aligned_bytes = ROUND_UP(bytes, alignment);

    // Try to find a suitable free region
    struct paging_region *prev = NULL;
    struct paging_region *freeList = st->free_list;
    while (freeList != NULL) {
        if (freeList->region_size >= aligned_bytes) { // Found a suitable region
            *buf = (void *)freeList->base_addr;

            // Adjust the free list entry
            if (freeList->region_size == aligned_bytes) {
                // Exact match, remove the current region from the list
                if (prev == NULL) {
                    st->free_list = freeList->next;
                } else {
                    prev->next = freeList->next;
                }
                slab_free(&st->slab_allocator, freeList);
            } else {
                // Partial allocation, update the base address and size
                freeList->base_addr += aligned_bytes;
                freeList->region_size -= aligned_bytes;
            }
            return SYS_ERR_OK;
        }
        prev = freeList;
        freeList = freeList->next;
    }


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

    // printf("Reserved virtual address range [%p - %p] as lazily allocated\n",
    //        (void *)vaddr, (void *)(vaddr + aligned_bytes));

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
    printf("FINISHED frame attr FUNXTION");
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
    struct capref mapping;
    //bool is_child = (st != get_current_paging_state())

    debug_printf("Allocating new page table: Type=%d, Slot=%llu\n", type, slot);

    // debug_printf("invoke alloctae_new_pagetable\n");
    slab_refill_check(&(st->slab_allocator));
    // Allocate a new page table from the slab allocator.
    parent->children[slot] = (struct page_table*)slab_alloc(&(st->slab_allocator));
    if (parent->children[slot] == NULL) {
        USER_PANIC("Failed to allocate page table from slab\n");
    }

    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    pt_alloc(st, type, &(parent->children[slot]->self));


    struct capref parent_mapping;
    struct capref parent_dest;
    struct capref parent_src;


    bool is_child = (st != get_current_paging_state());
    if (is_child) {
        slot_alloc(&parent_mapping);
        slot_alloc(&parent_dest);
        slot_alloc(&parent_src);
        cap_copy(parent_mapping, mapping);
        cap_copy(parent_dest, parent->self);
        cap_copy(parent_src, parent->children[slot]->self);
    } else {
        parent_mapping = mapping;
        parent_dest = parent->self;
        parent_src = parent->children[slot]->self;
    }
    // Now, proceed with the mapping.
    err = vnode_map(parent_dest, parent_src, slot, VREGION_FLAGS_READ_WRITE, offset, pte_ct, parent_mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        return err;
    }

    // Initialize the newly allocated page table
    for (int i = 0; i < NUM_PT_SLOTS; i++) {
        parent->children[slot]->children[i] = NULL;
    }

    debug_printf("Page table setup completed successfully.\n");
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
    printf("vaddr at start of function: 0x%lx\n", vaddr);
    printf("[paging_state] Current Paging State:\n");
    printf("  start_vaddr: %p\n", (void *)st->start_vaddr);
    printf("  current_vaddr: %p\n", (void *)st->current_vaddr);

    errval_t result;
    int pages_mapped;

    // Determine the total number of pages to map based on the provided bytes
    int total_pages = ROUND_UP(bytes, BASE_PAGE_SIZE) / BASE_PAGE_SIZE;
    int remaining_pages = total_pages;
    lvaddr_t original_vaddr = vaddr;
    
    bool is_child = !(st == get_current_paging_state());
    printf("is child: %p\n", is_child);


    while (remaining_pages > 0) {
        printf("ITERATION FIXED");

        // Calculate page table indices for the current virtual address
        int l0_idx = VMSAv8_64_L0_INDEX(vaddr);
        int l1_idx = VMSAv8_64_L1_INDEX(vaddr);
        int l2_idx = VMSAv8_64_L2_INDEX(vaddr);
        int l3_idx = VMSAv8_64_L3_INDEX(vaddr);

        // Helper function to allocate and map page tables with temporary VNode copies for the child
        struct capref vnode_cap;
        if (is_child) {
            // Temporarily copy VNode capability into the parent’s CSpace
            errval_t temp_err = slot_alloc(&vnode_cap);
            if (err_is_fail(temp_err)) {
                return temp_err;
            }
            temp_err = cap_copy(vnode_cap, st->root->self);
            if (err_is_fail(temp_err)) {
                cap_destroy(vnode_cap);
                return temp_err;
            }
            printf("Temporary VNode copy created in parent CSpace for child mapping.\n");
        } else {
            vnode_cap = st->root->self;
        }


        // Allocate and initialize page tables (L1, L2, L3) if necessary
        if (st->root->children[l0_idx] == NULL) {
            printf("before allocate root slot: Cnode=%d, Slot=%llu\n", st->root->cap.cnode, st->root->cap.slot);

            result = allocate_new_pagetable(st, l0_idx, 0, 1, ObjType_VNode_AARCH64_l1, st->root);
            printf("L1 pagetable allocated, checking state of st->root->children[%d]: %p\n", l0_idx, st->root->children[l0_idx]);
            if (err_is_fail(result)) {
                if (is_child) cap_destroy(vnode_cap);
                printf("Error allocating L1 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        if (st->root->children[l0_idx]->children[l1_idx] == NULL) {
            result = allocate_new_pagetable(st, l1_idx, 0, 1, ObjType_VNode_AARCH64_l2, 
                                            st->root->children[l0_idx]);
            if (err_is_fail(result)) {
                if (is_child) cap_destroy(vnode_cap);
                printf("Error allocating L2 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        if (st->root->children[l0_idx]->children[l1_idx]->children[l2_idx] == NULL) {
            result = allocate_new_pagetable(st, l2_idx, 0, 1, ObjType_VNode_AARCH64_l3, 
                                            st->root->children[l0_idx]->children[l1_idx]);
            if (err_is_fail(result)) {
                if (is_child) cap_destroy(vnode_cap);
                printf("Error allocating L3 pagetable: %s\n", err_getstring(result));
                return result;
            }
        }

        struct capref map_slot;
        result = st->slot_alloc->alloc(st->slot_alloc, &map_slot);
        if (err_is_fail(result)) {
            if (is_child) cap_destroy(vnode_cap);
            return err_push(result, LIB_ERR_SLOT_ALLOC);
        }

        // Map the maximum number of pages that can fit into the L3 page table
        pages_mapped = MIN((int)(NUM_PT_SLOTS - l3_idx), remaining_pages);
        debug_printf("Number of pages mapped: %d\n", pages_mapped);

        struct capref parent_mapping;
        struct capref parent_dest;
        struct capref parent_src;


        if (is_child) {
            slot_alloc(&parent_mapping);
            slot_alloc(&parent_dest);
            slot_alloc(&parent_src);
            cap_copy(parent_mapping, map_slot);
            cap_copy(parent_dest, st->root->children[l0_idx]->children[l1_idx]->children[l2_idx]->self);
            cap_copy(parent_src, frame);
        } else {
            parent_mapping = map_slot;
            parent_dest = st->root->children[l0_idx]->children[l1_idx]->children[l2_idx]->self;
            parent_src = frame;
        }



        result = vnode_map(parent_dest, 
                           parent_src, VMSAv8_64_L3_INDEX(vaddr), flags, offset + (BASE_PAGE_SIZE * (total_pages - remaining_pages)), 
                           pages_mapped, parent_mapping);
        if (err_is_fail(result)) {
            if (is_child) cap_destroy(vnode_cap);
            printf("vnode_map failed during leaf node mapping: %s\n", err_getstring(result));
            return result;
        }

        // Cleanup: Destroy the temporary VNode cap if created
        if (is_child) {
            cap_destroy(vnode_cap);
            printf("Temporary VNode cap destroyed after child mapping.\n");
        }

        vaddr += BASE_PAGE_SIZE;
        for (int j = VMSAv8_64_L3_INDEX(vaddr); j < NUM_PT_SLOTS; j++) {
            st->root->children[l0_idx]->children[l1_idx]->children[l2_idx]->children[l3_idx] = (void*)1;
            vaddr += BASE_PAGE_SIZE;
        }

        remaining_pages -= pages_mapped;
        // printf("after mapping vaddr: %p\n", vaddr);

        // printf("Addin the mapped region to the mapped_list\n");

        struct mapped_region *new_mapped = slab_alloc(&st->slab_allocator);
        if (new_mapped == NULL) {
            return LIB_ERR_SLAB_ALLOC_FAIL;
        }

        new_mapped->base_addr = original_vaddr;
        new_mapped->region_size = ROUND_UP(bytes, BASE_PAGE_SIZE);
        new_mapped->flags = flags;
        new_mapped->frame_cap = frame;
        new_mapped->offset = offset;
        new_mapped->next = st->mapped_list;
        new_mapped->mapping_cap = map_slot;
        st->mapped_list = new_mapped;

        printf("Mapped region [%p - %p] added to mapped_list\n", (void *)original_vaddr, (void *)(original_vaddr + new_mapped->region_size));

        result = slab_refill_check(&(st->slab_allocator));
        if (err_is_fail(result)) {
            printf("Slab allocation error: %s\n", err_getstring(result));
            return LIB_ERR_SLAB_REFILL;
        }
    }
    printf("FINISHED FIXED FUNCTION\n");
    return SYS_ERR_OK;
}




void page_fault_handler(void *faulting_address)
{
    errval_t err;
    // printf("Page fault occurred at address: %p\n", (void*)faulting_address);

    struct paging_state *st = get_current_paging_state();

    // Convert the faulting address to `lvaddr_t`
    lvaddr_t aligned_faulting_address = (lvaddr_t)faulting_address & ~(BASE_PAGE_SIZE - 1); // Align address
    lvaddr_t page_faulting_addr = (lvaddr_t)faulting_address;

    printf("Page fault occurred at aligned address: %p\n", aligned_faulting_address);

    printf("SLOT for faulting address: %p\n", VMSAv8_64_L3_INDEX(page_faulting_addr));
    printf("SLOT for aligned address: %p\n", VMSAv8_64_L3_INDEX(aligned_faulting_address));



    // Find the region where the page fault occurred
    struct paging_region *region = st->region_list;
    while (region != NULL) {
        // Check if the faulting address lies within this region
        if ((genvaddr_t)aligned_faulting_address >= region->base_addr &&
            (genvaddr_t)aligned_faulting_address < region->base_addr + region->region_size) {
            break;
        }
        region = region->next;
    }


    // No region found, handle the error
    if (region == NULL) { 
        USER_PANIC("Page fault occurred at an unmapped region: %p\n", faulting_address);
        return;
    }

    // // If the region is not lazily allocated, raise an error
    // if (region->type != PAGING_REGION_LAZY) {
    //     USER_PANIC("Page fault outside lazily allocated region: %p\n", faulting_address);
    //     return;
    // }

    // Proceed with lazy allocation and mapping
    // printf("Allocating and mapping frame for lazily allocated region\n");

    struct capref frame;  
    err = frame_alloc(&frame, region->region_size, NULL); // Allocate a frame
    if (err_is_fail(err)) {
        USER_PANIC("Frame allocation failed: %s\n", err_getstring(err));
        return;
    }

    if(region->type == PAGING_REGION_MAPPED) {
        paging_unmap(get_current_paging_state(),(void *)region->base_addr);
        err = paging_map_fixed_attr_offset(st, aligned_faulting_address, frame, region->region_size, 0, region->flags);
        region->type = PAGING_REGION_LAZY;
        return;
    }

    // Map the frame to the virtual address space
    err = paging_map_fixed_attr_offset(st, aligned_faulting_address, frame, region->region_size, 0, region->flags);
    if (err_is_fail(err)) {
        USER_PANIC("Frame mapping failed: %s\n", err_getstring(err));
        return;
    }

    region->type = PAGING_REGION_MAPPED;
    slab_refill_check(&(st->slab_allocator));

    // printf("Successfully handled page fault for lazy allocation at %p\n", faulting_address);
}


/**
 * @brief Adds a region to the free list in the paging state, maintaining the sorted order
 *        by base address and merging adjacent regions if possible.
 *
 * @param[in] st           The paging state to add the region to.
 * @param[in] base_addr    The base address of the region to add.
 * @param[in] region_size  The size of the region to add.
 *
 * @return SYS_ERR_OK on success, or an error indicating failure.
 */
errval_t add_to_free_list(struct paging_state *st, lvaddr_t base_addr, size_t region_size) {
    // Allocate a new region node using the slab allocator
    struct paging_region *new_region = slab_alloc(&st->slab_allocator);
    if (new_region == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Initialize the new region
    new_region->base_addr = base_addr;
    new_region->region_size = region_size;
    new_region->next = NULL;

    // Insert the new region into the free list, maintaining sorted order by base address
    struct paging_region *prev = NULL;
    struct paging_region *curr = st->free_list;

    while (curr != NULL && curr->base_addr < new_region->base_addr) {
        prev = curr;
        curr = curr->next;
    }

    // Insert the new region between prev and curr
    if (prev == NULL) {
        // Insert at the head of the list
        new_region->next = st->free_list;
        st->free_list = new_region;
    } else {
        prev->next = new_region;
        new_region->next = curr;
    }

    // Merge adjacent regions if possible to reduce fragmentation
    merge_adjacent_regions(st);

    return SYS_ERR_OK;
}


/**
 * @brief Merges adjacent regions in the free list to reduce fragmentation.
 *
 * @param[in] st  The paging state containing the free list.
 */
void merge_adjacent_regions(struct paging_state *st) {
    struct paging_region *curr = st->free_list;

    while (curr != NULL && curr->next != NULL) {
        // Check if the current region is adjacent to the next region
        if (curr->base_addr + curr->region_size == curr->next->base_addr) {
            // Merge the current region with the next one
            curr->region_size += curr->next->region_size;

            // Remove the next region from the list
            struct paging_region *next = curr->next;
            curr->next = next->next;
            slab_free(&st->slab_allocator, next);
        } else {
            curr = curr->next;
        }
    }
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
errval_t paging_unmap(struct paging_state *st, const void *region) {
    // printf("[paging_unmap] Invoked with region starting at: %p\n", region);

    struct mapped_region *prev = NULL;
    struct mapped_region *curr = st->mapped_list;

    // Find the mapped region
    while (curr != NULL) {
        if (curr->base_addr == (genvaddr_t)region) {
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) {
        printf("[paging_unmap] Error: Region not found for address: %p\n", region);
        return LIB_ERR_VSPACE_VREGION_NOT_FOUND;
    }

    // Check if the region has already been unmapped
    if (curr->is_unmapped) {
        printf("[paging_unmap] Warning: Region already unmapped: %p\n", region);
        return SYS_ERR_OK; // Return success, as it's already unmapped
    }

    // Unmap using the stored mapping capability
    errval_t err = vnode_unmap(st->root->children[VMSAv8_64_L0_INDEX(curr->base_addr)]
                               ->children[VMSAv8_64_L1_INDEX(curr->base_addr)]
                               ->children[VMSAv8_64_L2_INDEX(curr->base_addr)]->self, 
                               curr->mapping_cap);
    if (err_is_fail(err)) {
        printf("[paging_unmap] Error: Failed to unmap vnode: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VNODE_UNMAP);
    }

    // Mark the region as unmapped
    curr->is_unmapped = true;

    // Remove the region from the mapped_list
    if (prev == NULL) {
        st->mapped_list = curr->next;
    } else {
        prev->next = curr->next;
    }

    // Free the mapped_region structure
    slab_free(&st->slab_allocator, curr);
    // printf("[paging_unmap] Freed mapped_region structure for address: %p\n", (void *)region);

    // Add the unmapped region back to the free list
    add_to_free_list(st, curr->base_addr, curr->region_size);

    return SYS_ERR_OK;
}
