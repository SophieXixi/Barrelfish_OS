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

#include <grading/io.h>
#include <grading/state.h>
#include <grading/options.h>
#include <grading/tests.h>


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
    grading_printf("pt_alloc: Allocating page table of type %d\n", type);


    assert(type == ObjType_VNode_AARCH64_l0 || type == ObjType_VNode_AARCH64_l1
           || type == ObjType_VNode_AARCH64_l2 || type == ObjType_VNode_AARCH64_l3);

    // try to get a slot from the slot allocator to hold the new page table
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC); 
    }

    printf("pt_alloc: Slot allocated, creating vnode\n");

    // create the vnode in the supplied slot
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    printf("pt_alloc: Successfully created page table vnode\n");

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
 * @brief initializes the paging state struct for the current process
 *
 * @param[in] st           the paging state to be initialized
 * @param[in] start_vaddr  start virtual address to be managed
 * @param[in] root         capability to the root leve page table
 * @param[in] ca           the slot allocator instance to be used
 *
 * @return SYS_ERR_OK on success, or LIB_ERR_* on failure
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr, struct capref root,
                           struct slot_allocator *ca)
{
    // make compiler happy about unused parameters
    (void)root;

    // TODO (M1):
    //  - Implement basic state struct initialization
     

    // TODO (M2):
    //  -  Implement page fault handler that installs frames when a page fault
    //     occurs and keeps track of the virtual address space
    
    
    st->current_vaddr = start_vaddr;      
    st->start_vaddr = start_vaddr;          
    st->slot_alloc = ca;
    return LIB_ERR_NOT_IMPLEMENTED;
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
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref root, struct slot_allocator *ca)
{
    // make compiler happy about unused parameters
    (void)st;
    (void)start_vaddr;
    (void)root;
    (void)ca;

    // TODO (M3): Implement state struct initialization
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    printf("Invoke the function paging_init\n");
    struct capref cap;
    // TODO (M1): Call paging_init_state for &current

    // TODO (M2): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.
    
    set_current_paging_state(&current);
    paging_init_state(&current, 0, cap, current.slot_alloc);
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
    grading_printf("paging alloc\n");
    if (bytes == 0 || alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return ERR_INVALID_ARGS;
    }

    bool next_free_addr;
    size_t size;
    if (bytes < BASE_PAGE_SIZE) {
        size = 1;
    } else if (bytes % BASE_PAGE_SIZE == 0) {
        size = bytes / BASE_PAGE_SIZE;
    } else {
        size = bytes / BASE_PAGE_SIZE + 1;
    }

    size_t count = 0;
    size_t track;
    size_t start_addr = st->next_free_viraddr;
    if (st->next_free_viraddr % alignment != 0) {
        next_free_addr = false;
        track = 1;
    } else {
        next_free_addr = true;
        track = 0;
    }
    grading_printf("paging alloc: before while looping \n");
    while (count < size) {
        if (st->page_table[start_addr + track] == 0) {    // if the continuous blocks are free
            count ++;
        } else {    // some blocks are used, so no enough continuous blocks available, start from beginning
            count = 0;
        }
        track ++;
    }
    grading_printf("paging alloc: after while loop\n");
    if (next_free_addr && count == track) {   // the first available address can be used
        st->next_free_viraddr = start_addr + count;
    }
    *buf = (void*)(start_addr + track - count);
    return SYS_ERR_OK;

    /**
     * TODO(M1):
     *    - use a linear allocation scheme. (think about what allocation sizes are valid)
     *
     * TODO(M2): Implement this function
     *   - Find a region of free virtual address space that is large enough to
     *     accomodate a buffer of size `bytes`.
     */
    

    return LIB_ERR_NOT_IMPLEMENTED;
}




/**
 * @brief maps a frame at a free virtual address region and returns its address
 *
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

    grading_printf("paging map frame: before validating input\n");

    // Validate input parameters
    if (!st || !buf || bytes == 0) {
        return ERR_INVALID_ARGS;
    }

    errval_t err;

    // grading_printf("Before allocating VA");

    // Use a linear allocator to choose a virtual address
    lvaddr_t vaddr = st->next_free_viraddr;
    st->next_free_viraddr += bytes;

    grading_printf("paging map frame: before validating size\n");
    size_t pages;
    size_t alignment = 1;

    // Ensure the size fits in a single L3 page table (512 entries per L3 table, each mapping 4KB)
    if (bytes > (512 * BASE_PAGE_SIZE)) {
        return LIB_ERR_PMAP_ADDR_NOT_FREE;  // Error: cannot map across multiple L3 page tables in M1
    } else if (bytes < BASE_PAGE_SIZE) {
        pages = 1;
    } else if (bytes % BASE_PAGE_SIZE == 0) {
        pages = bytes / BASE_PAGE_SIZE;
    } else {
        pages = bytes / BASE_PAGE_SIZE + 1;
    }
    while (pages != 1) {
        pages = pages / 2;
        alignment = alignment * 2;
    }   // 1 -> 1; 2->2; 3->(1,2)->4; 5->(2,2)->(1,4)->8; 7->(3,2)->(1,4)->8
    if (alignment != 1) {
        alignment = alignment * 2;
    }
    grading_printf("paging map frame: after set the alignment\n");
    // printf(st->slot_alloc->alloc);
    grading_printf("Function address: %p\n", st->slot_alloc[0]);


    err = paging_alloc(st, buf, bytes, alignment);
    if (err == SYS_ERR_OK) {
        err = st->slot_alloc->alloc(st->slot_alloc, &frame);
    } 
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Allocation failed in paging.");
        return err;  // Handle the error
    }
    return SYS_ERR_OK;

    grading_printf("slot index calc");

    // Calculate the slot index in the L3 page table where this mapping should occur
    size_t slot_index = (vaddr >> BASE_PAGE_BITS) & 0x1FF;  // L3 page table has 512 entries

    grading_printf("Before VNODE mapping");

    // Use the vnode_map to map the frame into the existing L3 page table
    // cap_vroot is the root capability, already created by the kernel for the init process
    err = vnode_map(cap_vroot, frame, slot_index, flags, offset, bytes / BASE_PAGE_SIZE, NULL_CAP);
    if (err_is_fail(err)) {
        grading_printf("vnode_map failed");
        return err_push(err, LIB_ERR_VNODE_MAP); // Error during the mapping
    }

    grading_printf("Success");

    // Return the mapped virtual address
    *buf = (void *)vaddr;

    return SYS_ERR_OK;
    
    // TODO(M2):
    // - General case: handle mappings that span multiple L3 page tables.
    // - Handle allocation of free regions in the virtual address space that are at least `bytes` in size.
    // - Map the user-provided frame at the chosen virtual address.
    // - Return the virtual address in the `buf` parameter.
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
    // make compiler happy about unused parameters
    (void)st;
    (void)vaddr;
    (void)frame;
    (void)bytes;
    (void)offset;
    (void)flags;

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
