/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

/*
 * Copyright (c) 2008, 2011, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <string.h>
#include <aos/debug.h>
#include <aos/solution.h>
#include <mm/mm.h>



/**
 * @brief initializes the memory manager instance
 *
 * @param[in] mm        memory manager instance to initialize
 * @param[in] objtype   type of the capabilities stored in the memory manager
 * @param[in] ca        capability slot allocator to be used
 * @param[in] refill    slot allocator refill function to be used
 * @param[in] slab_buf  initial buffer space for slab allocators
 * @param[in] slab_sz   size of the initial slab buffer
 *
 * @return error value indicating success or failure
 *  - @retval SYS_ERR_OK if the memory manager was successfully initialized
 */
errval_t mm_init(struct mm *mm, enum objtype objtype, struct slot_allocator *ca,
                 slot_alloc_refill_fn_t refill, void *slab_buf, size_t slab_sz)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)objtype;
    (void)ca;
    (void)refill;
    (void)slab_buf;
    (void)slab_sz;

    // TODO: initialize the mm instance

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief destroys an mm instance
 *
 * @param[in] mm  memory manager instance to be freed
 *
 * @return error value indicating success or failure
 *  - @retval SYS_ERR_OK if the memory manager was successfully destroyed
 *
 * @note: does not free the mm object itself
 *
 * @note: This function is here for completeness. Think about how you would implement it.
 *        It's implementation is not required.
 */
errval_t mm_destroy(struct mm *mm)
{
    // make the compiler happy
    (void)mm;

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief adds new memory resources to the memory manager represented by the capability
 *
 * @param[in] mm   memory manager instance to add resources to
 * @param[in] cap  memory resources to be added to the memory manager instance
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK              on success
 *  - @retval MM_ERR_CAP_INVALID      if the supplied capability is invalid (size, alignment)
 *  - @retval MM_ERR_CAP_TYPE         if the supplied capability is not of the expected type
 *  - @retval MM_ERR_ALREADY_PRESENT  if the supplied memory is already managed by this allocator
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL  if the memory for the new node's meta data could not be allocate
 *
 * @note: the memory manager instance must be initialized before calling this function.
 *
 * @note: the function transfers ownership of the capability to the memory manager
 *
 * @note: to return allocated memory to the allocator, see mm_free()
 */
errval_t mm_add(struct mm *mm, struct capref cap)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)cap;

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief allocates memory with the requested size and alignment
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  size       minimum requested size of the memory region to allocate
 * @param[in]  alignment  minimum alignment requirement for the allocation
 * @param[out] retcap     returns the capability to the allocated memory
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_BAD_ALIGNMENT      if the requested alignment is not a power of two
 *  - @retval MM_ERR_OUT_OF_MEMORY      if there is not enough memory to satisfy the request
 *  - @retval MM_ERR_ALLOC_CONSTRAINTS  if there is memory, but the constraints are too tight
 *  - @retval MM_ERR_SLOT_ALLOC_FAIL    failed to allocate slot for new capability
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 *
 * @note The function allocates memory and returns a capability to it back to the caller.
 * The size of the returned capability is a multiple of BASE_PAGE_SIZE. Alignment requests
 * must be a power of two starting from BASE_PAGE_SIZE.
 *
 * @note The returned ownership of the capability is transferred to the caller.
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)alignment;
    (void)size;
    (void)retcap;

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief allocates memory of a given size within a given base-limit range (EXTRA CHALLENGE)
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  base       minimum requested address of the memory region to allocate
 * @param[in]  limit      maximum requested address of the memory region to allocate
 * @param[in]  size       minimum requested size of the memory region to allocate
 * @param[in]  alignment  minimum alignment requirement for the allocation
 * @param[out] retcap     returns the capability to the allocated memory
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_BAD_ALIGNMENT      if the requested alignment is not a power of two
 *  - @retval MM_ERR_OUT_OF_MEMORY      if there is not enough memory to satisfy the request
 *  - @retval MM_ERR_ALLOC_CONSTRAINTS  if there is memory, but the constraints are too tight
 *  - @retval MM_ERR_OUT_OF_BOUNDS      if the supplied range is not within the allocator's range
 *  - @retval MM_ERR_SLOT_ALLOC_FAIL    failed to allocate slot for new capability
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 *
 * The returned capability should be within [base, limit] i.e., base <= cap.base,
 * and cap.base + cap.size <= limit.
 *
 * The requested alignment should be a power two of at least BASE_PAGE_SIZE.
 */
errval_t mm_alloc_from_range_aligned(struct mm *mm, size_t base, size_t limit, size_t size,
                                     size_t alignment, struct capref *retcap)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)base;
    (void)limit;
    (void)size;
    (void)alignment;
    (void)retcap;

    // Perform allocations with the give alignment and size that are within the supplied
    /// base and limit range.

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief frees a previously allocated memory by returning it to the memory manager
 *
 * @param[in] mm   the memory manager instance to return the freed memory to
 * @param[in] cap  capability of the memory to be freed
 *
 * @return error value indicating the success of the operation
 *   - @retval SYS_ERR_OK            The memory was successfully freed and added to the allocator
 *   - @retval MM_ERR_NOT_FOUND      The memory was not allocated by this allocator
 *   - @retval MM_ERR_DOUBLE_FREE    The (parts of) memory region has already been freed
 *   - @retval MM_ERR_CAP_TYPE       The capability is not of the correct type
 *   - @retval MM_ERR_CAP_INVALID    The supplied cabability was invalid or does not exist.
 *
 * @pre  The function assumes that the capability passed in is no where else used.
 *       It is the only copy and there are no descendants of it. Calling functions need
 *       to ensure this. Later allocations can safely hand out the freed capability again.
 *
 * @note The memory to be freed must have been added to the `mm` instance and it must have been
 *       allocated before, otherwise an error is to be returned.
 *
 * @note The ownership of the capability slot is transferred to the memory manager and may
 *       be recycled for future allocations.
 */
errval_t mm_free(struct mm *mm, struct capref cap)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)cap;

    // TODO:
    //   - add the memory back to the allocator by markint the region as free
    //
    // You can assume that the capability was the one returned by a previous call
    // to mm_alloc() or mm_alloc_aligned(). For the extra challenge, you may also
    // need to handle partial frees, where a capability was split up by the client
    // and only a part of it was returned.

    UNIMPLEMENTED();
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief returns the amount of available (free) memory of the memory manager
 *
 * @param[in] mm   memory manager instance to query
 *
 * @return the amount of memory available in bytes in the memory manager
 */
size_t mm_mem_available(struct mm *mm)
{
    // make compiler happy about unused parameters
    (void)mm;

    UNIMPLEMENTED();
    return 0;
}


/**
 * @brief returns the total amount of memory this mm instances manages.
 *
 * @param[in] mm   memory manager instance to query
 *
 * @return the total amount of memory in bytes of the memory manager
 */
size_t mm_mem_total(struct mm *mm)
{
    // make compiler happy about unused parameters
    (void)mm;

    UNIMPLEMENTED();
    return 0;
}


/**
 * @brief obtains the range of free memory of the memory allocator instance
 *
 * @param[in]  mm     memory manager instance to query
 * @param[out] base   returns the minimum address of free memroy
 * @param[out] limit  returns the maximum address of free memory
 *
 * Note: This is part of the extra challenge. You can ignore potential (allocation)
 *       holes in the free memory regions, and just return the smallest address of
 *       a region than is free, and likewise the highest address
 */
void mm_mem_get_free_range(struct mm *mm, lpaddr_t *base, lpaddr_t *limit)
{
    // make compiler happy about unused parameters
    (void)mm;
    (void)base;
    (void)limit;

    UNIMPLEMENTED();
}
