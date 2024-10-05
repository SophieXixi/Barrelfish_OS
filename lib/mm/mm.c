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

#include <grading/io.h>
#include <grading/state.h>
#include <grading/options.h>
#include <grading/tests.h>
#include <grading/grading.h>


// Initialize the free list that is empty
void free_list_init(struct free_list *list) {
    list->head = NULL; 
}

void region_list_init(struct region_list *list) {
    list->head = NULL; 
}

bool is_power_of_two(size_t x) {
    if (x == 0) return false;
    while (x % 2 == 0) {
        x /= 2;
    }
    return x == 1;
}

errval_t insertNode_free_list(struct mm *mm, struct free_list *list, size_t size, uintptr_t base_addr, struct capref cap, genpaddr_t capability_base) {
    struct mm_node *new_node = slab_alloc(&mm->slab_allocator);
    if (new_node == NULL) {
        grading_printf("failed to allocate slab");
        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    new_node->size = size;
    new_node->base_addr = base_addr;
    new_node->cap = cap;
    new_node->next = NULL;
    new_node->prev = NULL; 
    new_node->used = false;
    new_node->capability_base = capability_base;
    new_node->offset = 0;

    // If the list is empty
    if (list->head == NULL) {
        list->head = new_node;
        return SYS_ERR_OK;
    }

    struct mm_node *current = list->head;
    struct mm_node *previous = NULL;

    // Traverse the list to find the appropriate insertion point based on base_addr
    while (current != NULL && current->base_addr < base_addr) {
        previous = current;
        current = current->next;
    }

    // If we are inserting at the beginning of the list
    if (previous == NULL) {
        new_node->next = list->head;
        if (list->head != NULL) {
            list->head->prev = new_node;  // Set previous of the old head
        }
        list->head = new_node;
    } else {
        // Insert the new node in between `previous` and `current`
        previous->next = new_node;
        new_node->prev = previous;  // Set the previous pointer of the new node

        new_node->next = current;
        if (current != NULL) {
            current->prev = new_node;  // Update `prev` pointer of the next node (current)
        }
    }

    return SYS_ERR_OK;
}


 
/**
 * @brief initializes the memory manager instance
 *
 * @param[in] mm        memory manager instance to initialize
 * @param[in] objtype   type of the capabilities stored in the memory manager
 * @param[in] ca        capability slot allocator to be used
 * @param[in] refill    slot allocator refill function to be used
 * @param[in] slab_buf  initial buffer space for slab allocators
 * @param[in] slab_sz   size of the initial slab buffer
 * Slot allocators: managing free capability slots
 * Slab allocators: a pool of memory that supports allocation requests of one specific size.
 *
 * @return error value indicating success or failure
 *  - @retval SYS_ERR_OK if the memory manager was successfully initialized
 */
errval_t mm_init(struct mm *mm, enum objtype objtype, struct slot_allocator *ca,
                 slot_alloc_refill_fn_t refill, void *slab_buf, size_t slab_sz)
{   
    (void)slab_buf;
    (void)slab_sz;
    
    grading_printf("entering mm_init");
     
    static char initial_slab_buffer[100 * 20480]; // A temporary static buffer
    
    // Parameter: void slab_init(struct slab_allocator *slabs, size_t objectsize, slab_refill_func_t refill_func);
    slab_init(&mm->slab_allocator, sizeof(struct mm_node), NULL);   //Initializes the slab allocator

    //Add the initlal buffer containing the memory to grow the slab. 
    slab_grow(&mm->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));

    //Set the slop allocator
    mm->ca = ca;

    mm->refill = refill;

    // This is the cap. type the mm will handle
    mm->objtype = objtype;

    free_list_init(&mm->free_list);  // Initialize the free list

    // Initialize total and free memory tracking
    mm->total_memory = 0;  // Total memory starts at 0, will be increased as memory is added
    mm->avaliable_memory = 0;   // No free memory initially, will be updated in mm_add()

    mm->mm_refilling_flag = false;

    return SYS_ERR_OK;
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
    // Free all the node that are already in the list
    struct mm_node *current = mm->free_list.head;
    while (current != NULL) {
        struct mm_node *next = current->next;
        slab_free(&mm->slab_allocator, current);
        current = next;
    }

    mm->free_list.head = NULL;
    mm->total_memory = 0;
    mm->avaliable_memory = 0;

    return SYS_ERR_OK;
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
    uintptr_t base_addr;
    size_t size;
    genpaddr_t capability_base;

    struct capability c;

    // get the cap
    errval_t err = cap_direct_identify(cap, &c);
     if (err_is_fail(err)) {
        grading_printf("cap invalid or undefiƒfned");
        return MM_ERR_CAP_INVALID;  
    }

    // Check the type of cap
    if (c.type != ObjType_RAM) {
        grading_printf("cap RAM is not of the type");
        return MM_ERR_CAP_TYPE;  
    }

    // Extract base address and size from the RAM capability represented by capbility
    base_addr = c.u.ram.base;
    size = c.u.ram.bytes;
    capability_base = c.u.ram.base;

    // Check if RAM does not exist of or not aligned
    if (size <= 0 || base_addr % BASE_PAGE_SIZE != 0) {
        return MM_ERR_CAP_INVALID;
    }

    // Check if the supplied memory is already managed by this allocator
    struct mm_node *curr = mm->free_list.head;
    while (curr != NULL) {
        struct capability curr_cap;
        err = cap_direct_identify(curr->cap, &curr_cap);
        if (err_is_fail(err)){
            return err_push(err, LIB_ERR_CAP_IDENTIFY);
        }
        if (base_addr == size) {
            return MM_ERR_ALREADY_PRESENT;
        }
        curr = curr->next;
    }

    // Check the free objects in the slab allocator and refill accordingly
    slab_refill_check(&(mm->slab_allocator));

    // Creating the freelist using mm node
    err = insertNode_free_list(mm, &(mm->free_list), size, base_addr,cap,capability_base);
    if (err_is_fail(err)) {
        grading_printf("fauled to allocate memory");
        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    if (err_is_fail(err)) {
        grading_printf("fauled to allocate memory");
        return MM_ERR_SLAB_ALLOC_FAIL;  
    }

    // Update memory manager tracking
    mm->total_memory += size;
    mm->avaliable_memory += size;

    return SYS_ERR_OK;
}

/**
 * @brief splits a node into two, creating a new node before the current node
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  node       the node to split on
 * @param[in]  size       the size to split off
 * @param[in]  used       whether to mark the node as used or free
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 */
static errval_t mm_split_beginning(struct mm *mm, struct mm_node *node, size_t size, bool used) {
    // allocate space for the new node and set the fields
    slab_refill_check(&(mm->slab_allocator));
    struct mm_node *splitoff = slab_alloc(&mm->slab_allocator);
    if (splitoff == NULL) {
        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    // set the new node's fields
    splitoff->base_addr = node->base_addr;
    splitoff->size = size;
    splitoff->used = used;
    splitoff->prev = node->prev;
    splitoff->next = node;
    splitoff->cap = node->cap;

    if (node->prev == NULL) {
        mm->free_list.head = splitoff;
    } else {
        node->prev->next = splitoff;
    }
    node->base_addr += size;
    node->size -= size;
    node->prev = splitoff;

    return SYS_ERR_OK;
}

/**
 * @brief splits a node in two, creating a new node after the current node
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  node       the node to split on
 * @param[in]  size       the size after which to make the split
 * @param[in]  used       whether to mark the node as used or free
 *
 * @return error value indicating the success of the operation
 *  - @retval SYS_ERR_OK                on success
 *  - @retval MM_ERR_SLAB_ALLOC_FAIL    failed to allocate memory for meta data
 */
static errval_t mm_split_end(struct mm *mm, struct mm_node *node, size_t size, bool used) {
    // allocate space for the new node and set the fields
    slab_refill_check(&(mm->slab_allocator));
    struct mm_node *splitoff = slab_alloc(&mm->slab_allocator);
    if (splitoff == NULL) {
        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    // set the new node's fields
    splitoff->base_addr = node->base_addr + size;
    splitoff->size = node->size - size;
    splitoff->used = used;
    splitoff->prev = node;
    splitoff->next = node->next;
    splitoff->cap = node->cap;
    
    node->size = size;
    node->next = splitoff;

    return SYS_ERR_OK;
}

/**
 * @brief allocates memory with the requested size and alignment
 *
 * @param[in]  mm         memory manager instance to allocate from
 * @param[in]  size       minimum requested size of the memory region to allocate
 * @param[in]  alignment  minimum alignment requirement for the allocation,  
                          controls the starting address of the allocated memory
                          so that the address is divisible by the alignment value.
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
 * BASE_PAGE_SIZE = 4kib
 * @note The returned ownership of the capability is transferred to the caller.
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
    printf("Calling mm_alloc_aligned\n");   
    printf("Before allocation - nslots: %u, space: %u\n", mm->ca->nslots, mm->ca->space);

    // Alignment Validation 
    if (alignment < BASE_PAGE_SIZE || !is_power_of_two(alignment) || (alignment & (alignment - 1)) != 0) {
        printf("Bad alognment in the mm_alloc_aligned\n");
        return MM_ERR_BAD_ALIGNMENT;
    } else if (mm->avaliable_memory < BASE_PAGE_SIZE) { // check avaliable memory
        return MM_ERR_OUT_OF_MEMORY;
    }

    size_t aligned_size = ROUND_UP(size, BASE_PAGE_SIZE);

    // Check the free objects in the slab allocator and refill accordingly
    slab_refill_check(&(mm->slab_allocator));

    struct mm_node *current = mm->free_list.head;
    
    while (current != NULL) {
        uintptr_t current_base = current->base_addr;
        size_t current_size = current->size;

        size_t alignment_offset = alignment - (current_base % alignment);

        if (alignment_offset == alignment) {
            alignment_offset = 0;
        } else if (alignment_offset >= current->size) {
            continue;
        }

        size_t potential_size = current_size - alignment_offset;
        if (current->used == false && potential_size >= aligned_size && potential_size >= BASE_PAGE_SIZE) {
            // split a node if there is enough space but the alignment is not correct
            if (alignment_offset > 0) {
                errval_t err = mm_split_beginning(mm, current, alignment_offset, false);
                if (err_is_fail(err)) {
                    return err;
                }
            }

            // split off the remainder of the node if possible
            if (current_size > aligned_size) {
                errval_t err = mm_split_end(mm, current, aligned_size, false);
                if (err_is_fail(err)) {
                    return err;
                }
            }

             // mark current mm ndoe as used
            current->used = true;

             // allocate a new slot for the return capability
            struct slot_prealloc *ca = (struct slot_prealloc *)mm->ca;
            errval_t err = slot_prealloc_alloc(ca, retcap);
            if (err_is_fail(err)) {
                return MM_ERR_SLOT_ALLOC_FAIL;
            }

            // copy the original capability into the new slot
            gensize_t aligned_offset = current->base_addr - current->capability_base;
            if (aligned_offset % alignment != 0) {
                aligned_offset = aligned_offset + alignment - (aligned_offset % alignment);
            }

            err = cap_retype(*retcap, current->cap, aligned_offset, ObjType_RAM, aligned_size);
            if (err_is_fail(err)) {
                debug_printf("retype error: size %d aligned size %d offset %p\n", size, aligned_size, aligned_offset);
                debug_printf(err_getstring(err));
                return MM_ERR_ALLOC_CONSTRAINTS;
            }

            err = slot_prealloc_refill(ca);
            if (err_is_fail(err)) {
                return MM_ERR_ALLOC_CONSTRAINTS;
            }
            return SYS_ERR_OK;

        }
        current = current->next;
    }

    // no suitable block was found
    return MM_ERR_OUT_OF_MEMORY;
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
     printf("Calling mm_alloc_aligned\n");   
    printf("Before allocation - nslots: %u, space: %u\n", mm->ca->nslots, mm->ca->space);

    // Alignment Validation 
    if (alignment < BASE_PAGE_SIZE || !is_power_of_two(alignment) || (alignment & (alignment - 1)) != 0) {
        printf("Bad alognment in the mm_alloc_aligned\n");
        return MM_ERR_BAD_ALIGNMENT;
    } else if (mm->avaliable_memory < BASE_PAGE_SIZE) { // check avaliable memory
        return MM_ERR_OUT_OF_MEMORY;
    }

    size_t aligned_size = ROUND_UP(size, BASE_PAGE_SIZE);

    // Check the free objects in the slab allocator and refill accordingly
    slab_refill_check(&(mm->slab_allocator));

    struct mm_node *current = mm->free_list.head;
    
    while (current != NULL) {
        uintptr_t current_base = current->base_addr;
        size_t current_size = current->size;

        size_t alignment_offset = alignment - (current_base % alignment);

        if (alignment_offset == alignment) {
            alignment_offset = 0;
        } else if (alignment_offset >= current->size) {
            continue;
        }

        // skip this node if it is not within bounds
        if (current_size < base || current_base + current_size > limit) {
            continue;
        }

        size_t potential_size = current_size - alignment_offset;
        if (current->used == false && potential_size >= aligned_size && potential_size >= BASE_PAGE_SIZE) {
            // split a node if there is enough space but the alignment is not correct
            if (alignment_offset > 0) {
                errval_t err = mm_split_beginning(mm, current, alignment_offset, false);
                if (err_is_fail(err)) {
                    return err;
                }
            }

            // split off the remainder of the node if possible
            if (current_size > aligned_size) {
                errval_t err = mm_split_end(mm, current, aligned_size, false);
                if (err_is_fail(err)) {
                    return err;
                }
            }

             // mark current mm ndoe as used
            current->used = true;

             // allocate a new slot for the return capability
            struct slot_prealloc *ca = (struct slot_prealloc *)mm->ca;
            errval_t err = slot_prealloc_alloc(ca, retcap);
            if (err_is_fail(err)) {
                return MM_ERR_SLOT_ALLOC_FAIL;
            }

            // copy the original capability into the new slot
            gensize_t aligned_offset = current->base_addr - current->capability_base;
            if (aligned_offset % alignment != 0) {
                aligned_offset = aligned_offset + alignment - (aligned_offset % alignment);
            }

            err = cap_retype(*retcap, current->cap, aligned_offset, ObjType_RAM, aligned_size);
            if (err_is_fail(err)) {
                debug_printf("retype error: size %d aligned size %d offset %p\n", size, aligned_size, aligned_offset);
                debug_printf(err_getstring(err));
                return MM_ERR_ALLOC_CONSTRAINTS;
            }

            err = slot_prealloc_refill(ca);
            if (err_is_fail(err)) {
                return MM_ERR_ALLOC_CONSTRAINTS;
            }
            return SYS_ERR_OK;

        }
        current = current->next;
    }

    // no suitable block was found
    return MM_ERR_OUT_OF_MEMORY;
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
    return mm->avaliable_memory;
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
    return mm->total_memory;
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