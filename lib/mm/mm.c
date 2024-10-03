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

#define REFILL_SIZE 4096

// Prototype for functions below
void free_list_init(struct free_list *list);
void region_list_init(struct region_list *list);
errval_t insertNode_free_list(struct mm *mm, struct free_list *list, size_t size, uintptr_t base_addr, struct capref cap);
bool is_power_of_two(size_t x);
errval_t slot_alloc_refill(struct slot_allocator *ca);
errval_t mm_refill(struct mm *mm);


errval_t mm_refill(struct mm *mm) {
    
    // Simulate a predefined block of memory
    static bool refilled = false;  // To simulate a single refill event
    if (refilled) {
        // Only refill once for this simple version
        debug_printf("Refill already done, no more memory available.\n");
        return MM_ERR_OUT_OF_MEMORY;
    }

    // Create a new capref for the new block
    struct capref new_cap;
    
    // Use ram_alloc to simulate adding a new memory block
    errval_t err = ram_alloc(&new_cap, REFILL_SIZE);
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate new memory block during refill\n");
        return MM_ERR_OUT_OF_MEMORY;
    }

    // Simulate identifying the newly allocated memory
    struct capability cap_info;
    err = cap_direct_identify(new_cap, &cap_info);
    if (err_is_fail(err)) {
        debug_printf("Failed to identify capability for new memory\n");
        return MM_ERR_CAP_INVALID;
    }

    // Insert the new memory region into the free list
    err = insertNode_free_list(mm, &(mm->free_list), cap_info.u.ram.bytes, cap_info.u.ram.base, new_cap);
    if (err_is_fail(err)) {
        debug_printf("Failed to insert new memory block into free list\n");
        return MM_ERR_SLAB_ALLOC_FAIL;
    }

    // Update memory tracking in mm
    mm->total_memory += REFILL_SIZE;
    mm->avaliable_memory += REFILL_SIZE;

    // Mark refill as done to avoid repeating in this simple version
    refilled = true;

    debug_printf("Memory refill successful: added %zu bytes\n", REFILL_SIZE);

    return SYS_ERR_OK;
}


// Initialize the free list that is empty
void free_list_init(struct free_list *list) {
    list->head = NULL; 
}

void region_list_init(struct region_list *list) {
    list->head = NULL; 
}

static size_t slab_refill(struct slab_allocator *slabs) {
    //grading_printf("Invoke the retype function");
    printf("Invoke the slab refill function\n");
    char *new_slab_buffer = malloc(4096);
    if (new_slab_buffer == NULL) {
        printf("Slab allocator refill failed: out of memory\n");
        return 0;
    }

    slab_grow(slabs, new_slab_buffer, 4096);

    // Return the size of the new slab buffer
    return 4096;
}


// Why fail at 254? -> running out of slots in the current CNode
// CNode has a fixed number of slots
errval_t slot_alloc_refill(struct slot_allocator *ca)
{
    printf("Invoke the slot_alloc_refill function\n");
    struct slot_prealloc *prealloc = (struct slot_prealloc *)ca;

    // Check if it's already refilling, and prevent recursive refilling
    if (prealloc->is_refilling) {
        return LIB_ERR_SLOT_ALLOC_NO_SPACE;
    }

    prealloc->is_refilling = true;  // Mark as refilling to prevent recursion
    errval_t err;

    // Allocate a new L2 CNode using the memory manager (prealloc->mm)
    struct capref new_cnode;
    err = mm_alloc_aligned(prealloc->mm, L2_CNODE_SLOTS * BASE_PAGE_SIZE, BASE_PAGE_SIZE, &new_cnode);
    if (err_is_fail(err)) {
        prealloc->is_refilling = false;
        return err_push(err, MM_ERR_SLOT_ALLOC_FAIL);  // Handle memory allocation failure
    }

    // Create the CNode using cnode_create_l2
    struct cnoderef root_cnode = { .croot = CPTR_ROOTCN, .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0), .level = CNODE_TYPE_OTHER };
    err = cnode_create_l2(&new_cnode, &root_cnode);
    if (err_is_fail(err)) {
        prealloc->is_refilling = false;
        return err_push(err, MM_ERR_SLOT_ALLOC_FAIL);  // Handle L2 CNode creation failure
    }

    // Update the meta with the new slots and reset the free slots count
    prealloc->meta[prealloc->current].cap = new_cnode;
    prealloc->meta[prealloc->current].free = L2_CNODE_SLOTS;  // Set to the full size of an L2 CNode

    prealloc->is_refilling = false; 
    grading_printf("Slot allocator refilled successfully\n");

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
    (void) refill;
    grading_printf("entering mm_init");
     
    static char initial_slab_buffer[20480]; // A temporary static buffer
    
    // Parameter: void slab_init(struct slab_allocator *slabs, size_t objectsize, slab_refill_func_t refill_func);
    slab_init(&mm->slab_allocator, sizeof(struct mm_node), slab_refill);   //Initializes the slab allocator

    //Add the initlal buffer containing the memory to grow the slab. 
    slab_grow(&mm->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));

    //Set the slop allocator
    mm->ca = ca;

    // This is the cap. type the mm will handle
    mm->objtype = objtype;

    free_list_init(&mm->free_list);  // Initialize the free list

    // Initialize total and free memory tracking
    mm->total_memory = 0;  // Total memory starts at 0, will be increased as memory is added
    mm->avaliable_memory = 0;   // No free memory initially, will be updated in mm_add()

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

// Probably need to be sorted. Srot based on the base address
errval_t insertNode_free_list(struct mm *mm , struct free_list *list, size_t size, uintptr_t base_addr, struct capref cap) {
   struct mm_node *new_node = slab_alloc(&mm->slab_allocator);
    if (new_node == NULL) {
        grading_printf("failed to allocate slab");
        return MM_ERR_SLAB_ALLOC_FAIL;  
    }

    new_node->size = size;
    new_node->base_addr = base_addr;
    new_node->cap = cap;
    new_node->next = NULL;
    new_node->offset = 0;

    // if it is a empty list
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
        list->head = new_node;
    } else {
        // Insert the new node in between previous and current
        previous->next = new_node;
        new_node->next = current;
    }

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

    struct capability c;

    errval_t err = cap_direct_identify(cap, &c);
     if (err_is_fail(err)) {
        grading_printf("cap invalid or undefiƒfned");
        return MM_ERR_CAP_INVALID;  
    }

    if (c.type != ObjType_RAM) {
        grading_printf("cap RAM is not of the type");
        return MM_ERR_CAP_TYPE;  
    }

    // Extract base address and size from the RAM capability represented by capbility
    base_addr = c.u.ram.base;
    size = c.u.ram.bytes;

    // Insert node two both lists
    err = insertNode_free_list(mm, &(mm->free_list), size, base_addr,cap);
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

bool is_power_of_two(size_t x) {
    if (x == 0) return false;
    while (x % 2 == 0) {
        x /= 2;
    }
    return x == 1;
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
    printf("call mm_alloc_aligned\n");   

    // Alignment Validation
    if (alignment < BASE_PAGE_SIZE || !is_power_of_two(alignment)) {
        return MM_ERR_BAD_ALIGNMENT;
    }

    struct mm_node *current = mm->free_list.head;
    struct mm_node *previous = NULL;
    size_t portionNum = 0;//debug
    
    while (current != NULL) {
        uintptr_t current_base = current->base_addr;
        size_t current_size = current->size;
        
        if (current_size >= size) {
            uintptr_t aligned_base = (current_base + alignment - 1) & ~(alignment - 1);
            size_t remaining_size = current_base + current_size - aligned_base;

            if (remaining_size >= size) {
                errval_t err = slot_alloc(retcap);
                if (err_is_fail(err)) {
                    return MM_ERR_SLOT_ALLOC_FAIL;
                }

                errval_t err_2 = cap_retype(*retcap, current->cap, aligned_base - current_base, ObjType_RAM, size);
                if (err_is_fail(err_2)) {
                    return MM_ERR_SLOT_ALLOC_FAIL;
                }
                
                current->size = aligned_base - current_base;

                struct mm_node *new_node = slab_alloc(&mm->slab_allocator);
                if (new_node == NULL) {
                    return MM_ERR_SLAB_ALLOC_FAIL;
                }
                new_node->offset = aligned_base - current_base;
                new_node->size = size;
                new_node->base_addr = aligned_base;
                new_node->cap = *retcap;
                new_node->next = current->next;

                if (remaining_size > size) {
                    struct mm_node *remaining_node = slab_alloc(&mm->slab_allocator);
                    if (remaining_node == NULL) {
                        return MM_ERR_SLAB_ALLOC_FAIL;
                    }
                    remaining_node->base_addr = aligned_base + size;
                    remaining_node->size = remaining_size - size;
                    remaining_node->next = new_node->next;
                    remaining_node->cap = current -> cap;
                    remaining_node -> offset = aligned_base - current_base + size;


                    new_node->next = remaining_node;
                }

                current->next = new_node;
                mm->avaliable_memory -= size;

                return SYS_ERR_OK;
            }
        }

        previous = current;
        current = current->next;
        portionNum++;
    }

    // If no suitable block found, attempt to refill and retry allocation
    printf("No suitable block found, attempting refill...\n");
    errval_t refill_err = mm_refill(mm);
    if (err_is_ok(refill_err)) {
        return mm_alloc_aligned(mm, size, alignment, retcap); // Retry allocation after refill
    }

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
    // Step 1: Alignment validation
    if (alignment < BASE_PAGE_SIZE || !is_power_of_two(alignment)) {
        return MM_ERR_BAD_ALIGNMENT;
    }
 

    struct mm_node *current = mm->free_list.head;
    struct mm_node *previous = NULL;
    size_t portionNum = 0;

    // Step 2: Traverse the free list to find a block that fits within the base-limit range
    while (current != NULL) {
        uintptr_t current_base = current->base_addr;
        size_t current_size = current->size;

        // Check if current block fits within the base-limit range
        if (current_base >= base && current_base + current_size <= limit) {

            // Align the current base address
            uintptr_t aligned_base = (current_base + alignment - 1) & ~(alignment - 1);
            
            // Check if aligned base and size fits within the limit
            if (aligned_base >= base && aligned_base + size <= limit) {
                
                // Ensure that the remaining size after alignment is sufficient for the request
                size_t remaining_size = current_base + current_size - aligned_base;
                if (remaining_size >= size) {

                    // Allocate a new slot for the capability
                    errval_t err = slot_alloc(retcap);
                    if (err_is_fail(err)) {
                        return MM_ERR_SLOT_ALLOC_FAIL;
                    }

                    // Retype the capability for the aligned memory block
                    err = cap_retype(*retcap, current->cap, aligned_base - current_base, ObjType_RAM, size);
                    if (err_is_fail(err)) {
                        return MM_ERR_SLOT_ALLOC_FAIL;
                    }

                    // Update the current node to account for the memory allocated
                    current->size = aligned_base - current_base;

                    // Allocate a new node for the allocated memory block
                    struct mm_node *new_node = slab_alloc(&mm->slab_allocator);
                    if (new_node == NULL) {
                        return MM_ERR_SLAB_ALLOC_FAIL;
                    }

                    new_node->size = size;
                    new_node->base_addr = aligned_base;
                    new_node->cap = *retcap;
                    new_node->next = current->next;

                    // Handle the remaining memory after the allocated block
                    if (remaining_size > size) {
                        struct mm_node *remaining_node = slab_alloc(&mm->slab_allocator);
                        if (remaining_node == NULL) {
                            return MM_ERR_SLAB_ALLOC_FAIL;
                        }
                        remaining_node->base_addr = aligned_base + size;
                        remaining_node->size = remaining_size - size;
                        remaining_node->next = new_node->next;

                        new_node->next = remaining_node;
                    }

                    // Link the new node into the list
                    current->next = new_node;

                    // Update memory manager's available memory
                    mm->avaliable_memory -= size;

                    return SYS_ERR_OK;
                }
            }
        }

        // Move to the next node in the free list
        previous = current;
        current = current->next;
        portionNum++;
    }

    // If no suitable block is found
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
    // TODO:
    //   - add the memory back to the allocator by markint the region as free
    //
    // You can assume that the capability was the one returned by a previous call
    // to mm_alloc() or mm_alloc_aligned(). For the extra challenge, you may also
    // need to handle partial frees, where a capability was split up by the client
    // and only a part of it was returned.

    // struct capability c;
    // bool found_flag = false;

    // errval_t err = cap_direct_identify(cap, &c);
    // if (err_is_fail(err)) {
    //     grading_printf("cap invalid or undefined");
    //     return MM_ERR_CAP_INVALID; 
    // }

    // if (c.type != ObjType_RAM) {
    //     grading_printf("cap RAM is not of the type");
    //     return MM_ERR_CAP_TYPE; 
    // }

    // uintptr_t base_addr = c.u.ram.base;
    // size_t size = c.u.ram.bytes;

  
    // struct mm_node *previous = NULL;
    

    // // We need find the the match of the list
    // while (current != NULL) {
    //     if (current->base_addr == base_addr && current->size == size) {
    //         found_flag = true;

    //         // Remove the node from the region list
        

    //         // Free the memory from the region list, now add it to the free list
    //         err = insertNode_free_list(mm, &(mm->free_list), size, base_addr, cap);
    //         if (err_is_fail(err)) {
    //             grading_printf("failed to insert node into free list");
    //             return MM_ERR_SLAB_ALLOC_FAIL;  // Failed to insert into the free list
    //         }

    //         // Update available memory tracking
    //         mm->avaliable_memory += size;

    //         // merge
    //         //merge_adjacent_blocks(mm);
    //         //slab_free(&mm->slab_allocator, current);  // Free the node
    //         return SYS_ERR_OK;
    //     }

    //     previous = current;
    //     current = current->next;
    // }

    // if (!found_flag) {
    //     return  MM_ERR_DOUBLE_FREE;  // Memory region not found in the region list, it is alredy freed.
    // }

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









// errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
//     // Step 1: Alignment Validation
//     if (alignment < BASE_PAGE_SIZE || !is_power_of_two(alignment)) { // Cannot be smaller than base page size
//         return MM_ERR_BAD_ALIGNMENT;
//     }

//     // Traverse the free list to find a block that satisfies the alignment and size
//     struct mm_node *current = mm->free_list.head;
//     struct mm_node *prev = NULL; // Track the previous node to help with list modification
//     size_t portionNum = 0;

//     while (current != NULL) {
//         uintptr_t current_base = current->base_addr;
//         size_t current_size = current->size;

//         // Check if the current block has enough size to fit the requested `size`
//         if (current_size >= size) {

//             // Align current_base down to the nearest aligned address that can fit `size`
//             uintptr_t aligned_base = (current_base + alignment - 1) & ~(alignment - 1);

//             // Calculate the remaining size after alignment
//             size_t remaining_size = current_base + current_size - aligned_base;

//             // If the remaining size is enough to fit `size`
//             if (remaining_size >= size) {
                
//                 // Allocate new capability slot
//                 errval_t err = slot_alloc(retcap);
//                 if (err_is_fail(err)) {
//                     grading_printf("error exists in slot_alloc\n");
//                     return MM_ERR_SLOT_ALLOC_FAIL;
//                 }

//                 // Retype the capability for the aligned memory block
//                 errval_t err_2 = cap_retype(*retcap, current->cap, aligned_base - current_base, ObjType_RAM, size);
//                 if (err_is_fail(err_2)) {
//                     grading_printf("error exists in retype\n");
//                     char *s = err_getstring(err_2);
//                     grading_printf("%s\n", s);
//                     grading_printf("size: %zu, remaining_size: %zu\n", size, remaining_size);
//                     grading_printf("current_base: 0x%lx\n", (unsigned long)current_base);
//                     grading_printf("aligned_base: 0x%lx\n", (unsigned long)aligned_base);
//                     grading_printf("Failed when trying to allocate %zu th portion in the list\n", portionNum);
//                     return MM_ERR_SLOT_ALLOC_FAIL;
//                 }

//                 // Update the current node with the remaining size before the aligned base
//                 current->size = aligned_base - current_base;

//                 // If there's remaining space after the allocated block, add it as another free node
//                 if (remaining_size > size) {
//                     struct mm_node *remaining_node = slab_alloc(&mm->slab_allocator);
//                     if (remaining_node == NULL) {
//                         return MM_ERR_SLAB_ALLOC_FAIL;
//                     }
//                     // Update the metadata for the remaining node
//                     remaining_node->base_addr = aligned_base + size;
//                     remaining_node->size = remaining_size - size;
//                     remaining_node->cap = current->cap;

//                     // Insert the remaining node after the current node
//                     remaining_node->next = current->next;
//                     current->next = remaining_node;
//                 } 

//                 // Check if the current node's size becomes 0
//                 if (current->size == 0) {
//                     // Remove current node from the list
//                     if (prev != NULL) {
//                         prev->next = current->next;
//                     } else {
//                         // If current is the head, update the head
//                         mm->free_list.head = current->next;
//                     }
//                     // Free the current node
//                     slab_free(&mm->slab_allocator, current);
//                 }

//                 // Update the memory manager's available memory
//                 mm->avaliable_memory -= size;

//                 // Return success for the current allocation
//                 return SYS_ERR_OK;
//             }
//         }

//         // Move to the next node in the free list
//         prev = current;
//         current = current->next;
//         portionNum++;
//     }

//     // If no suitable block is found
//     return MM_ERR_OUT_OF_MEMORY;
// }

