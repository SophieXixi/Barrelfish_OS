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
    // Log function entry
    printf("Invoking paging_init_state\n");
    printf("Parameters: start_vaddr = %p, root = %p\n", (void*)start_vaddr, (void*)&root);

    errval_t err;

    // Step 1: Initialize basic paging state
    printf("Step 1: Initializing basic paging state\n");
    st->current_vaddr = start_vaddr;
    st->start_vaddr = start_vaddr;
    st->slot_alloc = ca;

    // Step 2: Initialize slab allocator for page table structures
    printf("Step 2: Initializing slab allocator\n");
    static char initial_slab_buffer[100 * 20480];
    slab_init(&st->slab_allocator, sizeof(struct page_table), NULL);
    slab_grow(&st->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));
    printf("Slab allocator initialized with a buffer of size %zu\n", sizeof(initial_slab_buffer));

    // Step 3: Set the root page table
    st->root = root;

    // Step 4: Map the L1 page table
    printf("Step 4: Mapping L1 page table\n");
    struct capref mapping;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc(st, ObjType_VNode_AARCH64_l1, &st->L1); // Creates the VNode for the L1 table

    // VMSAv8_64_L0_INDEX(st->current_vaddr): index in the L0 page table where the L1 page table should be mapped
    // VREGION_FLAGS_READ_WRITE: Permission
    err = vnode_map(st->root, st->L1, VMSAv8_64_L0_INDEX(st->current_vaddr), VREGION_FLAGS_READ_WRITE, 0, 1, mapping);
    if (err_is_fail(err)) {
        printf("Error: Failed to map L1 page table: %s\n", err_getstring(err));
        return -1;
    }

    // Step 5: Map the L2 page table
    printf("Step 5: Mapping L2 page table\n");
    struct capref mapping2;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping2);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc(st, ObjType_VNode_AARCH64_l2, &st->L2);
    err = vnode_map(st->L1, st->L2, VMSAv8_64_L1_INDEX(st->current_vaddr), VREGION_FLAGS_READ_WRITE, 0, 1, mapping2);
    if (err_is_fail(err)) {
        printf("Error: Failed to map L2 page table: %s\n", err_getstring(err));
        return -1;
    }

    // Step 6: Map the L3 page table
    printf("Step 6: Mapping L3 page table\n");
    struct capref mapping3;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping3);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    pt_alloc(st, ObjType_VNode_AARCH64_l3, &st->L3);
    err = vnode_map(st->L2, st->L3, VMSAv8_64_L2_INDEX(st->current_vaddr), VREGION_FLAGS_READ_WRITE, 0, 1, mapping3);
    if (err_is_fail(err)) {
        printf("Error: Failed to map L3 page table: %s\n", err_getstring(err));
        return -1;
    }

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
        printf("Invoke the paging_map_frame_attr_offset\n");

    // Check if the size is aligned with the base page size
    if (bytes % BASE_PAGE_SIZE != 0) {
        printf("Error: bytes = %zu is not aligned with BASE_PAGE_SIZE = %zu\n", bytes, BASE_PAGE_SIZE);
        return MM_ERR_BAD_ALIGNMENT;
    }

    // Step 1: Find or allocate a free virtual address range
    errval_t err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);  // Allocate free virtual address space
    if (err_is_fail(err)) {
        printf("Error: Failed to allocate virtual address range\n");
        return err;
    }

    lvaddr_t vaddr = (lvaddr_t)*buf;  // The starting virtual address of the allocated range
    printf("Allocated virtual address range starting at %p\n", (void*)vaddr);

    // TODO: Add hashmap lookup logic to check if each level page table exists.
    // If not, create the page table and update the hashmap.

    // Repeat this process for L2 and L3 page tables.
    // Ensure all required page tables for the specified virtual address range are created.

    // Step 3: Map the frame at the free virtual address using vnode_map
    printf("Mapping frame at virtual address %p\n", (void*)vaddr);
    err = vnode_map(st->L3, frame, VMSAv8_64_L3_INDEX(vaddr), flags, offset, 1, st->root);
    if (err_is_fail(err)) {
        printf("Error: vnode_map failed (virtual address = %p)\n", (void*)vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    printf("Frame successfully mapped at virtual address %p\n", (void*)vaddr);

    // Step 4: Update internal state
    *buf = (void*)vaddr;  // Return the base virtual address of the mapped frame
    st->current_vaddr += bytes;  // Update current_vaddr for next allocation

    printf("Returning base virtual address %p\n", *buf);
    printf("Updated current_vaddr to %p\n", (void*)st->current_vaddr);
    printf("Exiting paging_map_frame_attr_offset successfully\n");

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
    
    printf("Invoke the paging_map_frame_attr_offset\n");

    // Check if the size is aligned with the base page size
    if (bytes % BASE_PAGE_SIZE != 0) {
        printf("Error: bytes = %zu is not aligned with BASE_PAGE_SIZE = %zu\n", bytes, BASE_PAGE_SIZE);
        return MM_ERR_BAD_ALIGNMENT;
    }

    // Allocate a slot for the mapping (where the frame is placed in the page table)
    struct capref mapping;
    printf("Allocating slot for mapping\n");
    errval_t err = st->slot_alloc->alloc(st->slot_alloc, &(mapping));
    if (err_is_fail(err)) {
        printf("Error: Slot allocation failed\n");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    printf("Slot allocated successfully\n");

    // Map the frame at the found virtual address using vnode_map
    printf("Mapping frame at virtual address %p\n", (void*)st->current_vaddr);
    err = vnode_map(st->L3, frame, VMSAv8_64_L3_INDEX(st->current_vaddr), flags, offset, 1, mapping);
    if (err_is_fail(err)) {
        printf("Error: vnode_map failed (virtual address = %p)\n", (void*)st->current_vaddr);
        return err_push(err, LIB_ERR_VNODE_MAP);
    }
    printf("Frame successfully mapped at virtual address %p\n", (void*)st->current_vaddr);

    // Return the base virtual address of the mapped frame
    *buf = (void*)st->current_vaddr;
    printf("Returning base virtual address %p\n", *buf);

    // Update the current virtual address for the next allocation
    st->current_vaddr += bytes;
    printf("Updated current_vaddr to %p\n", (void*)st->current_vaddr);

    printf("Exiting paging_map_frame_attr_offset successfully\n");
    return SYS_ERR_OK;
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
