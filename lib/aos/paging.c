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
//static char stack_first[EXCEPTION_STACK_SIZE];
errval_t allocate_new_pagetable(struct paging_state *st, capaddr_t slot, 
                  uint64_t offset, uint64_t pte_ct, enum objtype type, struct page_table *parent);
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
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, st->slab_buf, SLAB_STATIC_SIZE(NUM_PTS_ALLOC, sizeof(struct page_table)));

    // Allocate memory for the root page table using the slab allocator
    st->root = slab_alloc(&st->slab_allocator);
    if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Set up the root page table properties
    st->root = slab_alloc(&st->slab_allocator);
    if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    st->root->offset = 0;
    st->root->self = root;  
    st->root->numFree = NUM_PT_SLOTS;
    st->root->parent = NULL;
    for (int i = 0; i < NUM_PT_SLOTS; i++) {
         st->root->children[i] = NULL;
    }

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

     // Initialize basic fields for the paging state struct
    st->current_vaddr = start_vaddr;
    st->start_vaddr = start_vaddr;
    st->slot_alloc = ca;

    // Initialize the slab allocator for paging regions
    //static char slab_buffer[100 * 20480];  // Adjust size as necessary
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, st->slab_buf, SLAB_STATIC_SIZE(NUM_PTS_ALLOC, sizeof(struct page_table)));
    // Allocate memory for the root page table using the slab allocator
    st->root = slab_alloc(&st->slab_allocator);
    if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    // Set up the root page table properties
    st->root = slab_alloc(&st->slab_allocator);
    if (st->root == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    st->root->offset = 0;
    st->root->self = root;  
    st->root->numFree = NUM_PT_SLOTS;
    st->root->parent = NULL;
    for (int i = 0; i < NUM_PT_SLOTS; i++) {
         st->root->children[i] = NULL;
    }


    return SYS_ERR_OK;
    
}

// void pf_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs)
// { 
//     (void)subtype; 
//     (void)regs;
//     if (type == EXCEPT_PAGEFAULT) {
//         printf("Page fault occurred at address: %p\n", addr);
//         printf("subtype: %p\n", subtype);
//         page_fault_handler(addr);  
//     } else {
//         USER_PANIC(": unhandled exception (type %d) on %p\n", type, addr);
//     }
// }


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
    // void *stack_top = stack_first + EXCEPTION_STACK_SIZE;
    // stack_top = (void *)ALIGNED_STACK_TOP(stack_top);
    
    // err = thread_set_exception_handler(pf_handler, NULL, stack_first, stack_top,
    //                                NULL, NULL);
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
    // Align the requested size
    size_t aligned_bytes = ROUND_UP(bytes, alignment);

    // Start the search from the current virtual address
    genvaddr_t vaddr = st->current_vaddr;

    // Tracks how much contiguous free space has been identified.
    size_t space = 0;

    // Extract the indices for page table levels
    //begins searching from the most recent state of the virtual memory
    genvaddr_t currentL0 = VMSAv8_64_L0_INDEX(vaddr);
    genvaddr_t currentL1 = VMSAv8_64_L1_INDEX(vaddr);
    genvaddr_t currentL2 = VMSAv8_64_L2_INDEX(vaddr);
    genvaddr_t currentL3 = VMSAv8_64_L3_INDEX(vaddr);

    bool resetVaddr = false;

    // Find a contiguous free region large enough for `aligned_bytes`
    while (space < aligned_bytes) {
        if (st->root->children[currentL0] == NULL ||
            st->root->children[currentL0]->children[currentL1] == NULL ||
            st->root->children[currentL0]->children[currentL1]->children[currentL2] == NULL ||
            st->root->children[currentL0]->children[currentL1]->children[currentL2]->children[currentL3] == NULL) {
            
            // Increment space by the page size
            space += BASE_PAGE_SIZE;
        } else {
            // Conflict: Reset search
            resetVaddr = true;
        }

        // Move to the next L3 slot
        currentL3++;
        if (currentL3 >= NUM_PT_SLOTS) {
            currentL3 = 0;
            currentL2++;
        }
        if (currentL2 >= NUM_PT_SLOTS) {
            currentL2 = 0;
            currentL1++;
        }
        if (currentL1 >= NUM_PT_SLOTS) {
            currentL1 = 0;
            currentL0++;
        }
        if (currentL0 >= NUM_PT_SLOTS) {
            // If all slots are exhausted, wrap around
            // restarts search for free space from the beginning of the virtual memory range.
            vaddr = st->start_vaddr;
            currentL0 = VMSAv8_64_L0_INDEX(vaddr);
            currentL1 = VMSAv8_64_L1_INDEX(vaddr);
            currentL2 = VMSAv8_64_L2_INDEX(vaddr);
            currentL3 = VMSAv8_64_L3_INDEX(vaddr);
            resetVaddr = false;
            space = 0; // Reset space
        }

        if (resetVaddr) {
            // Recalculate the virtual address and reset space
            resetVaddr = false;
            vaddr = VADDR_CALCULATE(currentL0, currentL1, currentL2, currentL3, 0);
            space = 0;
        }
    }

    // Allocate the region starting at the calculated `vaddr`
    *buf = (void *)vaddr;

    // Update `st->current_vaddr` to move forward
    st->current_vaddr = ROUND_UP(vaddr + bytes + BASE_PAGE_SIZE, BASE_PAGE_SIZE);

    // Track the lazily allocated region in the paging state's region list
    //struct paging_region *new_region = slab_alloc(&st->slab_allocator);
    // if (new_region == NULL) {
    //     return LIB_ERR_SLAB_ALLOC_FAIL;
    // }

    // // Initialize the lazily allocated region
    // new_region->base_addr = vaddr;             // Start of the reserved virtual address range
    // new_region->region_size = aligned_bytes;   // Size of the allocated virtual memory region
    // new_region->flags = VREGION_FLAGS_READ_WRITE; // Default permissions
    // new_region->type = PAGING_REGION_LAZY;     // Mark as lazily allocated
    // new_region->next = st->region_list;        // Add it to the head of the region list
    // st->region_list = new_region;              // Update the region list

    // Return success
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
    
    size_t aligned_bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    // This eager allocation works
    genvaddr_t vaddr = (genvaddr_t)*buf;
    errval_t err = paging_map_fixed_attr_offset(st, vaddr, frame, aligned_bytes, offset, flags);
    if (err_is_fail(err)) {
        printf("vnode_map failed after paging_map_fixed_attr_offset: %s\n", err_getstring(err));
        return -1;
    }

    return SYS_ERR_OK;
}


errval_t allocate_new_pagetable(struct paging_state *st, capaddr_t slot, 
                  uint64_t offset, uint64_t pte_ct, enum objtype type, struct page_table *parent) {
    errval_t err;

    debug_printf("Allocating new page table: Type=%d, Slot=%llu\n", type, slot);

    parent->children[slot] = (struct page_table*)slab_alloc(&(st->slab_allocator));
    if (parent->children[slot] == NULL) {
       USER_PANIC("Failed to allocate page table from slab\n");
    }
    
    struct capref mapping;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = pt_alloc(st, type, &(parent->children[slot]->self));
    if (err_is_fail(err)) {
        debug_printf("cap that fails: \n");
    }
    
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
    }  else {
        parent_mapping = mapping;
        parent_dest = parent->self;
        parent_src = parent->children[slot]->self;
    }


    // err = vnode_map(parent->self, parent->children[slot]->self, 
    //                 slot, VREGION_FLAGS_READ_WRITE, offset, pte_ct, parent_mapping);
    err = vnode_map(parent_dest, parent_src, slot, VREGION_FLAGS_READ_WRITE, offset, pte_ct, parent_mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed mapping: %s\n", err_getstring(err));
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
    // printf("vaddr at start of function: 0x%lx\n", vaddr);
    // printf("[paging_state] Current Paging State:\n");
    // printf("  start_vaddr: %p\n", (void *)st->start_vaddr);
    // printf("  current_vaddr: %p\n", (void *)st->current_vaddr);

    errval_t err;
    int numMapped;

    // TODO(M2):
    //  - General case: you will need to handle mappings spanning multiple leaf page tables.
    //  - Make sure to update your paging state to reflect the newly mapped region
    //  - Map the user provided frame at the provided virtual address
    //
    // Hint:
    //  - think about what mapping configurations are actually possible
    //
        
    // number of pages to map
    int originalNumPages = ROUND_UP(bytes, BASE_PAGE_SIZE) / BASE_PAGE_SIZE;
    int numPages = originalNumPages;

    bool is_child = !(st == get_current_paging_state());
    printf("is child: %p\n", is_child);

    // map pages in L3 page table-sized chunks
    for (int i = 0; numPages > 0; i++) {

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



        // If necessary allocate and initialize a new L1 pagetable
        if (st->root->children[VMSAv8_64_L0_INDEX(vaddr)] == NULL) {
            // mapNewPt() is a helper function that adds a new page 
            // table of the type provided to the page table provided
            err = allocate_new_pagetable(st, VMSAv8_64_L0_INDEX(vaddr), offset, 1, ObjType_VNode_AARCH64_l1, st->root);
            if (err_is_fail(err)) {
                if (is_child) cap_destroy(vnode_cap);
                debug_printf("pt_alloc_l1 failed: %s\n", err_getstring(err));
                return err;
            }
        }
        // If necessary allocate and initialize a new L2 pagetable
        if (st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->
                      children[VMSAv8_64_L1_INDEX(vaddr)] == NULL) {
            err = allocate_new_pagetable(st, VMSAv8_64_L1_INDEX(vaddr), offset, 1, ObjType_VNode_AARCH64_l2, 
                     st->root->children[VMSAv8_64_L0_INDEX(vaddr)]);
            if (err_is_fail(err)) {
                if (is_child) cap_destroy(vnode_cap);
                debug_printf("pt_alloc_l2 failed: %s\n", err_getstring(err));
                return err;
            }
        }
        // If necessary allocate and initialize a new L3 pagetable
        if (st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->
                      children[VMSAv8_64_L2_INDEX(vaddr)] == NULL) {
            // debug_printf("mapping new L3 PT, L2: %d\n", VMSAv8_64_L2_INDEX(vaddr));
            // debug_print_cap_at_capref(st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->self);
            err = allocate_new_pagetable(st, VMSAv8_64_L2_INDEX(vaddr), offset, 1, ObjType_VNode_AARCH64_l3, 
                     st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->
                               children[VMSAv8_64_L1_INDEX(vaddr)]);
            if (err_is_fail(err)) {
                if (is_child) cap_destroy(vnode_cap);
                debug_printf("pt_alloc_l3 failed: %s\n", err_getstring(err));
                return err;
            }
        }
        
        
        // allocate a slot for the mapping of the pages in the L3 page table
        struct capref mapping;
        err = st->slot_alloc->alloc(st->slot_alloc, &(mapping));
        if (err_is_fail(err)) {
            if (is_child) cap_destroy(vnode_cap);
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }

        // map the maximum number of pages that we can fit in this L3 page table
        // debug_printf("awful capref at L0 index %d L1 index %d L2 index %d and L3 index %d:\n", VMSAv8_64_L0_INDEX(vaddr), VMSAv8_64_L1_INDEX(vaddr),VMSAv8_64_L2_INDEX(vaddr), VMSAv8_64_L3_INDEX(vaddr));
        // debug_print_cap_at_capref(st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->
        //                           children[VMSAv8_64_L1_INDEX(vaddr)]->
        //                           children[VMSAv8_64_L2_INDEX(vaddr)]->self);
        numMapped = MIN((int)(NUM_PT_SLOTS - VMSAv8_64_L3_INDEX(vaddr)), numPages);

        struct capref parent_mapping;
        struct capref parent_dest;
        struct capref parent_src;
        
        
        if (is_child) {
            slot_alloc(&parent_mapping);
            slot_alloc(&parent_dest);
            slot_alloc(&parent_src);
            cap_copy(parent_mapping, mapping);
            cap_copy(parent_dest, st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->children[VMSAv8_64_L2_INDEX(vaddr)]->self);
            cap_copy(parent_src, frame);
        } else {
            parent_mapping = mapping;
            parent_dest = st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->children[VMSAv8_64_L2_INDEX(vaddr)]->self;
            parent_src = frame;
        }


        // err = vnode_map(st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->
        //                           children[VMSAv8_64_L1_INDEX(vaddr)]->
        //                           children[VMSAv8_64_L2_INDEX(vaddr)]->self, frame,
        //                           VMSAv8_64_L3_INDEX(vaddr), flags, 
        //                           offset + (BASE_PAGE_SIZE * (originalNumPages - numPages)), numMapped, parent_mapping);
         err = vnode_map(parent_dest, 
                           parent_src, VMSAv8_64_L3_INDEX(vaddr), flags, offset + (BASE_PAGE_SIZE * (originalNumPages - numPages)), 
                           numMapped, parent_mapping);
        if (err_is_fail(err)) {
            if (is_child) cap_destroy(vnode_cap);
            debug_printf("vnode_map failed mapping leaf node: %s\n", err_getstring(err));
            return err;
        }
        
        // Cleanup: Destroy the temporary VNode cap if created
        if (is_child) {
            cap_destroy(vnode_cap);
            printf("Temporary VNode cap destroyed after child mapping.\n");
        }

        // book keeping for unmapping later
        st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->
                  children[VMSAv8_64_L2_INDEX(vaddr)]->children[VMSAv8_64_L3_INDEX(vaddr)] = slab_alloc(&st->slab_allocator);
        st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->
                  children[VMSAv8_64_L2_INDEX(vaddr)]->children[VMSAv8_64_L3_INDEX(vaddr)]->mapping = mapping;
        st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->
                  children[VMSAv8_64_L2_INDEX(vaddr)]->children[VMSAv8_64_L3_INDEX(vaddr)]->numBytes = bytes;
        
        // set all the rest of the children in this L3 page table to not null (so we see them as unused) 
        // except for the first one where we store our book keeping
        // TODO: potentially save the extra slots in our L3 page table if the optomization is needed.
        vaddr+=BASE_PAGE_SIZE;
        for (int j = VMSAv8_64_L3_INDEX(vaddr); j < NUM_PT_SLOTS; j++) {
            st->root->children[VMSAv8_64_L0_INDEX(vaddr)]->children[VMSAv8_64_L1_INDEX(vaddr)]->
                  children[VMSAv8_64_L2_INDEX(vaddr)]->children[VMSAv8_64_L3_INDEX(vaddr)] 
                  = (void*) 1;
            vaddr += BASE_PAGE_SIZE;
        }

        // update loop variable
        numPages -= numMapped;
        // printf("slab size:  %p\n", slab_freecount(&st->ma));
        // printf("slot size:  %p\n", st->slot_alloc->space);
        // refill the slab if necessary
        err = slab_refill_check(&(st->slab_allocator));
        if (err_is_fail(err)) {
            debug_printf("slab alloc error: %s\n", err_getstring(err));
            return LIB_ERR_SLAB_REFILL;
        }
    }
    
    return SYS_ERR_OK;
}




// void page_fault_handler(void *faulting_address)
// {
//     errval_t err;

//     struct paging_state *st = get_current_paging_state();

//     // Convert the faulting address to `lvaddr_t`
//     lvaddr_t aligned_faulting_address = (lvaddr_t)faulting_address & ~(BASE_PAGE_SIZE - 1); // Align address
//     lvaddr_t page_faulting_addr = (lvaddr_t)faulting_address;

//     printf("Page fault occurred at aligned address: %p\n", aligned_faulting_address);

//     printf("SLOT for faulting address: %p\n", VMSAv8_64_L3_INDEX(page_faulting_addr));
//     printf("SLOT for aligned address: %p\n", VMSAv8_64_L3_INDEX(aligned_faulting_address));



//     // Find the region where the page fault occurred
//     struct paging_region *region = st->region_list;
//     while (region != NULL) {
//         // Check if the faulting address lies within this region
//         if ((genvaddr_t)aligned_faulting_address >= region->base_addr &&
//             (genvaddr_t)aligned_faulting_address < region->base_addr + region->region_size) {
//             break;
//         }
//         region = region->next;
//     }


//     // No region found, handle the error
//     if (region == NULL) { 
//         USER_PANIC("Page fault occurred at an unmapped region: %p\n", faulting_address);
//         return;
//     }

//     // // If the region is not lazily allocated, raise an error
//     if (region->type != PAGING_REGION_LAZY) {
//         USER_PANIC("Page fault outside lazily allocated region: %p\n", faulting_address);
//         return;
//     }

//     // Proceed with lazy allocation and mapping
//     // printf("Allocating and mapping frame for lazily allocated region\n");

//     struct capref frame;  
//     err = frame_alloc(&frame, region->region_size, NULL); // Allocate a frame
//     if (err_is_fail(err)) {
//         USER_PANIC("Frame allocation failed: %s\n", err_getstring(err));
//         return;
//     }

//     // Map the frame to the virtual address space
//     err = paging_map_fixed_attr_offset(st, aligned_faulting_address, frame, region->region_size, 0, region->flags);
//     if (err_is_fail(err)) {
//         USER_PANIC("Frame mapping failed: %s\n", err_getstring(err));
//         return;
//     }

//     region->type = PAGING_REGION_MAPPED;
//     slab_refill_check(&(st->slab_allocator));

//     // printf("Successfully handled page fault for lazy allocation at %p\n", faulting_address);
// }


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
// errval_t add_to_free_list(struct paging_state *st, lvaddr_t base_addr, size_t region_size) {
//     // Allocate a new region node using the slab allocator
//     struct paging_region *new_region = slab_alloc(&st->slab_allocator);
//     if (new_region == NULL) {
//         return LIB_ERR_SLAB_ALLOC_FAIL;
//     }

//     // Initialize the new region
//     new_region->base_addr = base_addr;
//     new_region->region_size = region_size;
//     new_region->next = NULL;

//     // Insert the new region into the free list, maintaining sorted order by base address
//     struct paging_region *prev = NULL;
//     struct paging_region *curr = st->free_list;

//     while (curr != NULL && curr->base_addr < new_region->base_addr) {
//         prev = curr;
//         curr = curr->next;
//     }

//     // Insert the new region between prev and curr
//     if (prev == NULL) {
//         // Insert at the head of the list
//         new_region->next = st->free_list;
//         st->free_list = new_region;
//     } else {
//         prev->next = new_region;
//         new_region->next = curr;
//     }

//     // Merge adjacent regions if possible to reduce fragmentation
//     merge_adjacent_regions(st);

//     return SYS_ERR_OK;
// }


/**
 * @brief Merges adjacent regions in the free list to reduce fragmentation.
 *
 * @param[in] st  The paging state containing the free list.
 */
// void merge_adjacent_regions(struct paging_state *st) {
//     struct paging_region *curr = st->free_list;

//     while (curr != NULL && curr->next != NULL) {
//         // Check if the current region is adjacent to the next region
//         if (curr->base_addr + curr->region_size == curr->next->base_addr) {
//             // Merge the current region with the next one
//             curr->region_size += curr->next->region_size;

//             // Remove the next region from the list
//             struct paging_region *next = curr->next;
//             curr->next = next->next;
//             slab_free(&st->slab_allocator, next);
//         } else {
//             curr = curr->next;
//         }
//     }
// }




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
     // make compiler happy about unused parameters
    (void)st;
    (void)region;

    // TODO(M2):
    //  - implemet unmapping of a previously mapped region

    // check if the region is allocated.
    if (st->root->children[VMSAv8_64_L0_INDEX(region)]==NULL
        ||st->root->children[VMSAv8_64_L0_INDEX(region)]->
                    children[VMSAv8_64_L1_INDEX(region)]==NULL
        ||st->root->children[VMSAv8_64_L0_INDEX(region)]->
                    children[VMSAv8_64_L1_INDEX(region)]->
                    children[VMSAv8_64_L2_INDEX(region)]==NULL 
        ||st->root->children[VMSAv8_64_L0_INDEX(region)]->
                    children[VMSAv8_64_L1_INDEX(region)]->
                    children[VMSAv8_64_L2_INDEX(region)]->
                    children[VMSAv8_64_L3_INDEX(region)]==NULL
        ) {
        printf("region is not allocated\n");
        return SYS_ERR_VM_ALREADY_MAPPED;
    }
    // find out the size of the region to unmap (stored in each L3 page table 
    // since mappings are done by groups of L3 page tables)
    uint64_t bytes_to_unmap = st->root->children[VMSAv8_64_L0_INDEX(region)]->
                                        children[VMSAv8_64_L1_INDEX(region)]->
                                        children[VMSAv8_64_L2_INDEX(region)]->
                                        children[VMSAv8_64_L3_INDEX(region)]->numBytes;

    
    // continually unmap the existing mappings until we've gone over the limit. 
    uint64_t bytes_unmapped = 0;
    while (bytes_unmapped < bytes_to_unmap) {
        vnode_unmap(st->root->children[VMSAv8_64_L0_INDEX(region)]->
                              children[VMSAv8_64_L1_INDEX(region)]->
                              children[VMSAv8_64_L2_INDEX(region)]->self, 
                    st->root->children[VMSAv8_64_L0_INDEX(region)]->
                              children[VMSAv8_64_L1_INDEX(region)]->
                              children[VMSAv8_64_L2_INDEX(region)]->
                              children[VMSAv8_64_L3_INDEX(region)]->mapping);
        
        // be sure to mark the L3 PT slots unused
        for (uint64_t i = 0; i < MIN(NUM_PT_SLOTS, bytes_to_unmap-bytes_unmapped); i++) {
            st->root->children[VMSAv8_64_L0_INDEX(region)]->
                      children[VMSAv8_64_L1_INDEX(region)]->
                      children[VMSAv8_64_L2_INDEX(region)]->
                      children[VMSAv8_64_L3_INDEX(region)]->
                      children[i] = NULL;
        }
        bytes_unmapped += BASE_PAGE_SIZE * 512;
        region += BASE_PAGE_SIZE * 512;
    }
    return SYS_ERR_OK;
}
