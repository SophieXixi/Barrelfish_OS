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

#include <stdio.h>
#include <string.h>


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
    (void)start_vaddr;
    // Log function entry
    printf("Invoking paging_init_state\n");
    // printf("Parameters: start_vaddr = %p, root = %p\n", (void*)start_vaddr, (void*)&root);

    // Step 1: Initialize basic paging state
    printf("Step 1: Initializing basic paging state\n");

    struct pgtb pgtb;
    st->start_vaddr = start_vaddr;
    pgtb.parent     = NULL;
    st->meta_pt     = &pgtb;
    st->slot_alloc  = ca;
    st->l0          = NULL;

    // Step 2: Initialize slab allocator for page table structures
    printf("Step 2: Initializing slab allocator\n");
    static char initial_slab_buffer[100 * 20480];
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));
    // printf("Slab allocator initialized with a buffer of size %zu\n", sizeof(initial_slab_buffer));

    // Step 3: Set the root page table
    st->root = root;

    // Final Step: Print completion message
    printf("Paging initialization completed successfully\n");

    return SYS_ERR_OK;
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
    Lower part of the virtual address space -> kernel operations, higher part for user-space
    processes We here map the the upper part of the virtual address space
    */
    paging_init_state(&current, ((uint64_t)1) << 46, cap_vroot, get_default_slot_allocator());
    set_current_paging_state(&current);

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

// alloc a new page table L1
errval_t alloc_new_pt_l1(struct paging_state *st, size_t slot, struct pgtb_entry *new_l)
{
    // alloc new L1 page table
    errval_t err = st->slot_alloc->alloc(st->slot_alloc, &new_l->mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc_l1(st, &new_l->next_level_pt);  // Creates the VNode for the L1 table
    err = vnode_map(st->root, new_l->next_level_pt, slot, VREGION_FLAGS_READ_WRITE, 0, 1,
                    new_l->mapping);
    if (err_is_fail(err)) {
        // printf("Error: Failed to map L1 page table: %s\n", err_getstring(err));
        return SYS_ERR_VNODE_SLOT_INVALID;
    }
    new_l->meta_data = true;
    return SYS_ERR_OK;
}

// alloc a new page table L2
errval_t alloc_new_pt_l2(struct paging_state *st, struct capref dst, size_t slot,
                         struct pgtb_entry *new_l)
{
    // alloc new L1 page table
    errval_t err = st->slot_alloc->alloc(st->slot_alloc, &new_l->mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc_l2(st, &new_l->next_level_pt);  // Creates the VNode for the L1 table
    err = vnode_map(dst, new_l->next_level_pt, slot, VREGION_FLAGS_READ_WRITE, 0, 1, new_l->mapping);
    if (err_is_fail(err)) {
        // printf("Error: Failed to map L1 page table: %s\n", err_getstring(err));
        return SYS_ERR_VNODE_SLOT_INVALID;
    }
    new_l->meta_data = true;
    return SYS_ERR_OK;
}

// alloc a new page table l3
errval_t alloc_new_pt_l3(struct paging_state *st, struct pgtb_entry *new_l)
{
    // alloc new L1 page table
    errval_t err = st->slot_alloc->alloc(st->slot_alloc, &new_l->mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    new_l->meta_data = false;
    return SYS_ERR_OK;
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
    // calculate the required page

    lvaddr_t aligned_addr;
    
    struct vmm *curr = st->vmm_list->head;
    
    while (curr != NULL) {
        // Check if the current node has free space and is large enough for allocation
        if (!curr->used && curr->size >= bytes) {
            // Calculate the aligned start address
            aligned_addr = (curr->start_addr + alignment - 1) & ~(alignment - 1);

            // Ensure that the aligned address fits within the current node's space
            if ((aligned_addr + bytes) <= (curr->start_addr + curr->size)) {
                
                // Step 2: Split the current node
                size_t remaining_space = curr->size - (aligned_addr - curr->start_addr + bytes);

                // Create a new node for the remaining free space if needed
                if (remaining_space > 0) {
                    struct vmm *new_node = malloc(sizeof(struct vmm));
                    new_node->start_addr = aligned_addr + bytes;
                    new_node->size = remaining_space;
                    new_node->used = false;
                    new_node->next = curr->next;
                    new_node->prev = curr;

                    // Update the current node to reflect the allocated space
                    curr->next = new_node;
                    curr->size = aligned_addr - curr->start_addr + bytes;
                }

                // Mark the current node as used and store the address
                curr->used = true;
                *buf = (void *)aligned_addr;

                // Return the success code
                return SYS_ERR_OK;
            }
        }

        // Move to the next region
        curr = curr->next;
    }

    // If no space found, return an error
    return SYS_ERR_OK;
}



size_t adjust_alignment(size_t pages)
{
    size_t align = 1;
    if (pages == 1) {
        return 1;
    } else {
        size_t rest = 0;
        while (pages >= 2) {
            rest  = pages % 2;
            pages = pages / 2;
            align = align * 2;
        }
        if (rest == 1) {
            align = align * 2;
        }
    }
    return align;
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
    printf("page map frame: invoke the paging_map_frame_attr_offset\n");
    size_t target_page = adjust_size(bytes);
    size_t alignment   = adjust_alignment(target_page);
    // get the free virtual memory region
    printf("page map frame: before paging alloc\n");
    errval_t err   = paging_alloc(st, buf, bytes, alignment);
    lvaddr_t vaddr = (lvaddr_t)*buf;
    printf("page map frame: before alloc l0\n");
    // Allocate a slot for the mapping (where the frame is placed in the page table)
    // size_t pages_finished = 0;
    if (st->l0 == NULL) {
        struct page_table       l0;
        struct page_table_entry pte0;
        printf("page map frame: allocating slot for mapping\n");
        err = st->slot_alloc->alloc(st->slot_alloc, &pte0.mapping);
        if (err_is_fail(err)) {
            printf("Error: pt alloc failed\n");
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }
        err = pt_alloc(st, ObjType_VNode_AARCH64_l0, &l0.cap);
        if (err_is_fail(err)) {
            printf("Error: Slot allocation failed\n");
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }
        printf("page map frame: slot allocated successfully\n");
        // err = vnode_map(st->root, l0.cap, VMSAv8_64_L0_INDEX(st->start_vaddr), flags, 0, 1,
        // pte0.mapping); printf("vnode_map params: root: %p, l0.cap: %p, index: %lu, flags: %d,
        // offset: %lu, pages: %lu, mapping: %p\n", st->root, l0.cap, (((vaddr) >> 39) & 0x1FF),
        // flags, 50, 1, pte0.mapping); printf("vaddr: %p\n", vaddr); printf("L0 index calculation:
        // ((vaddr >> 39) & 0x1FF) = %lu\n", ((vaddr >> 39) & 0x1FF));
        l0.pte[VMSAv8_64_L0_INDEX(vaddr)] = &pte0;
        if (err_is_fail(err)) {
            printf("error: error: %d\n", err);
            printf("Error: l0 vnode_map failed (virtual address = %p)\n", vaddr);
            return err_push(err, LIB_ERR_VNODE_MAP);
        }
        st->l0 = &l0;
        printf("page map frame: l0 mapped successfully\n");
    }

    // Map the frame at the found virtual address using vnode_map
    // printf("Mapping frame at virtual address %p\n", vaddr);
    // L0 node

    // pt_alloc(st, ObjType_VNode_AARCH64_l0, &l0.cap);
    // err = st->slot_alloc->alloc(st->slot_alloc, &l0.cap);

    // L1 node
    struct page_table       l1;
    struct page_table_entry pte1;
    err = st->slot_alloc->alloc(st->slot_alloc, &pte1.mapping);
    if (err_is_fail(err)) {
        printf("Error: pt alloc failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = pt_alloc_l1(st, &l1.cap);
    if (err_is_fail(err)) {
        printf("Error: Slot allocation failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = vnode_map(st->l0->cap, l1.cap, VMSAv8_64_L0_INDEX(st->start_vaddr), flags, offset, 1,
                    pte1.mapping);
    printf("index: %lu\n", VMSAv8_64_L0_INDEX(st->start_vaddr));
    if (err_is_fail(err)) {
        printf("Error: vnode_map failed (virtual address = %p)\n", vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    l1.pte[VMSAv8_64_L1_INDEX(vaddr)]                  = &pte1;
    st->l0->pte[VMSAv8_64_L0_INDEX(vaddr)]->next_level = &l1;
    printf("page map frame: l1 mapped successfully\n");
    // L2 node
    struct page_table       l2;
    struct page_table_entry pte2;
    err = st->slot_alloc->alloc(st->slot_alloc, &pte2.mapping);
    if (err_is_fail(err)) {
        printf("Error: pt alloc failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = pt_alloc_l1(st, &l2.cap);
    if (err_is_fail(err)) {
        printf("Error: Slot allocation failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = vnode_map(st->l0->pte[VMSAv8_64_L0_INDEX(st->start_vaddr)]->next_level->cap, l2.cap,
                    VMSAv8_64_L1_INDEX(vaddr), flags, offset, 1, pte2.mapping);
    l2.pte[VMSAv8_64_L2_INDEX(vaddr)] = &pte2;
    if (err_is_fail(err)) {
        printf("Error: vnode_map failed (virtual address = %p)\n", vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    st->l0->pte[VMSAv8_64_L0_INDEX(vaddr)]->next_level->pte[VMSAv8_64_L1_INDEX(vaddr)]->next_level
        = &l2;
    printf("page map frame: l2 mapped successfully\n");
    // L3 node
    struct page_table       l3;
    struct page_table_entry pte3;
    err = st->slot_alloc->alloc(st->slot_alloc, &pte3.mapping);
    if (err_is_fail(err)) {
        printf("Error: pt alloc failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = pt_alloc_l1(st, &l3.cap);
    if (err_is_fail(err)) {
        printf("Error: Slot allocation failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = vnode_map(st->l0->pte[VMSAv8_64_L0_INDEX(st->start_vaddr)]
                        ->next_level->pte[VMSAv8_64_L1_INDEX(vaddr)]
                        ->next_level->pte[VMSAv8_64_L2_INDEX(vaddr)]
                        ->next_level->cap,
                    l3.cap, VMSAv8_64_L3_INDEX(vaddr), flags, offset, 1, pte3.mapping);
    if (err_is_fail(err)) {
        // printf("Error: vnode_map failed (virtual address = %p)\n", vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    l3.pte[VMSAv8_64_L3_INDEX(vaddr)] = &pte3;
    st->l0->pte[VMSAv8_64_L0_INDEX(vaddr)]
        ->next_level->pte[VMSAv8_64_L1_INDEX(vaddr)]
        ->next_level->pte[VMSAv8_64_L2_INDEX(vaddr)]
        ->next_level
        = &l3;
    err = vnode_map(st->l0->pte[VMSAv8_64_L0_INDEX(vaddr)]
                        ->next_level->pte[VMSAv8_64_L1_INDEX(vaddr)]
                        ->next_level->pte[VMSAv8_64_L2_INDEX(vaddr)]
                        ->next_level->pte[VMSAv8_64_L3_INDEX(vaddr)]
                        ->next_level->cap,
                    frame, VMSAv8_64_L3_INDEX(vaddr), flags, offset, target_page, pte3.mapping);
    if (err_is_fail(err)) {
        // printf("Error: vnode_map failed (virtual address = %p)\n", vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    // printf("Frame successfully mapped at virtual address %p\n", vaddr);
    // printf("Returning base virtual address %p\n", *buf);
    printf("page map frame: exiting paging_map_frame_attr_offset successfully\n");
    return SYS_ERR_OK;

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
}

// return the start address of target vaddr (start addr of the corresponding base page)
lvaddr_t adjust_vaddr(lvaddr_t vaddr)
{
    if (vaddr % BASE_PAGE_SIZE != 0) {
        return vaddr - vaddr % BASE_PAGE_SIZE;
    } else {
        return vaddr;
    }
}

// return the corresponding size needed for a whole number of base pages
size_t adjust_size(size_t bytes)
{
    if (bytes % BASE_PAGE_SIZE != 0) {
        return BASE_PAGE_SIZE * (bytes / BASE_PAGE_SIZE + 1);
    } else {
        return bytes / BASE_PAGE_SIZE;
    }
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
    (void)st;
    (void)vaddr;
    (void)frame;
    (void)bytes;
    (void)offset;
    (void)flags;
    // make compiler happy about unused parameters
    printf("Invoke the paging_map_fixed_attr_offset\n");
    // step 1: check the availability of the vaddr
    // bool content;
    // // content = st->meta_pt->pgtb_entry[VMSAv8_64_L0_INDEX()]
    // // step 2: map the frame
    // printf("Allocating slot for mapping\n");
    // struct capref mapping;
    // errval_t err = st->slot_alloc->alloc(st->slot_alloc, &(mapping));
    // if (err_is_fail(err)) {
    //     printf("Error: Slot allocation failed\n");
    //     return err_push(err, LIB_ERR_SLOT_ALLOC);
    // }
    // printf("Slot allocated successfully\n");
    // // Map the frame at the found virtual address using vnode_map
    // printf("Mapping frame at virtual address %p\n", target_vaddr);
    // err = vnode_map(st->L3, frame, VMSAv8_64_L3_INDEX(vaddr), flags, offset, 1, mapping);
    // if (err_is_fail(err)) {
    //     printf("Error: vnode_map failed (virtual address = %p)\n", vaddr);
    //     return err_push(err, LIB_ERR_VNODE_MAP);
    // }
    // printf("Frame successfully mapped at virtual address %p\n", vaddr);

    // TODO(M2):
    //  - General case: you will need to handle mappings spanning multiple leaf page tables.
    //  - Make sure to update your paging state to reflect the newly mapped region
    //  - Map the user provided frame at the provided virtual address
    //
    // Hint:
    //  - think about what mapping configurations are actually possible
    //
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)st;
    (void)region;

    // TODO(M2):
    //  - implemet unmapping of a previously mapped region
    return LIB_ERR_NOT_IMPLEMENTED;
}
