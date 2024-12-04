/**
 * \file
 * \brief Morecore implementation for malloc
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, 2019 ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * Copyright (c) 2022, The University of British Columbia
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/morecore.h>
#include <stdio.h>

// function signature for the morecore alloc function
typedef void *(*morecore_alloc_func_t)(size_t bytes, size_t *retbytes);
extern morecore_alloc_func_t sys_morecore_alloc;

// function signature for the morecore free function
typedef void (*morecore_free_func_t)(void *base, size_t bytes);
extern morecore_free_func_t sys_morecore_free;


// This define enables the use of a static 16MB mini heap in the data section.
//
// TODO (M2): disable this define and implement a dynamic heap allocator
//#define USE_STATIC_HEAP


#ifdef USE_STATIC_HEAP

// Size of the static heap (16MB)
#define HEAP_SIZE (1<<24)

/// @brief  the static heap (16MB)
static char mymem[HEAP_SIZE] = { 0 };
/// @brief end position of the static heap.
static char *endp = mymem + HEAP_SIZE;

/**
 * @brief Morecore allocator to back the heap with static memory
 *
 * @param[in]  bytes     Minimum number of bytes to allocated
 * @param[out] retbytes  Returns the number of actually allocated bytes
 */
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    struct morecore_state *state = get_morecore_state();

    size_t aligned_bytes = ROUND_UP(bytes, sizeof(Header));
    void *ret = NULL;
    if (state->freep + aligned_bytes < endp) {
        ret = state->freep;
        state->freep += aligned_bytes;
    }
    else {
        aligned_bytes = 0;
    }
    *retbytes = aligned_bytes;
    return ret;
}

/**
 * @brief Frees memory that has been previously allocated by `morecore_alloc`
 *
 * @param[in] base   Virtual address of the region to be freed
 * @param[in] bytes  Size of the region to be freed
 */
static void morecore_free(void *base, size_t bytes)
{
    // make compiler happy about unused parameters
    (void)base;
    (void)bytes;

    return;
}

/**
 * @brief initializes the morecore memory allocator backed by static memory
 *
 * @param[in] alignment  requested minimum alignment of the heap pages (mininum BASE_PAGE_SIZE)
 *
 * @return SYS_ERR_OK (should not fail)
 */
errval_t morecore_init(size_t alignment)
{
    // make compiler happy about unused parameters
    (void)alignment;

    struct morecore_state *state = get_morecore_state();

    debug_printf("initializing static heap\n");

    thread_mutex_init(&state->mutex);

    // initialize the free pointer with the start of the heap
    state->freep = mymem;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;
    return SYS_ERR_OK;
}

#else /* !USE_STATIC_HEAP */


// dynamic heap using lib/aos/paging features


/**
 * @brief Morecore memory allocator to back the heap region with dynamically allocated memory
 *
 * @param[in]  bytes     Minimum number of bytes to allocated
 * @param[out] retbytes  Returns the number of actually allocated bytes
 *
 * This function allocates a region of virtual addresses that are later on-demand mapped through
 * the page fault handling mechanism. In other words, this function doesn't actually allocate
 * any physical frames.
 *
 * Hint: As a design decision, think about whether you like to reserve a big region virtual memory
 *       and then manage this memory here, or whether you like to allocate a new region of virtual
 *       memory in response to each call to `morecore_alloc`. Think about the pros and cons of
 *       each approach.
 *
 * Hint: it may make sense to implement eager mapping first, then switch to lazy mapping and
 *       handling of the page faults on demand.
 */
void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    // void *buf;
    // struct morecore_state *state = get_morecore_state();
   
    // debug_printf("Allocating a frame for initial heap\n");
    
    // paging_alloc(get_current_paging_state(), &buf, bytes, state->alignment);

    // if (buf == NULL) {
    //     *retbytes = 0;
    //     return NULL;
    // }

    // *retbytes = bytes;

    // // Track the newly allocated region
    // struct allocated_region *new_region = slab_alloc(&state->slab_allocator);
    // if (new_region == NULL) {
    //     // Allocation tracking failed, free the memory
    //     paging_unmap(get_current_paging_state(), buf);
    //     *retbytes = 0;
    //     return NULL;
    // }

    // new_region->base = buf;
    // new_region->size = bytes;
    // new_region->next = state->allocated_list;
    // state->allocated_list = new_region;

    // debug_printf("Allocated and tracked memory region [%p - %p]\n", buf, (char *)buf + bytes);

    // return buf;
    struct morecore_state *state = get_morecore_state();
    printf("[DEBUG] Retrieved morecore state: %p\n", state);

    struct allocdBlock *curr = state->root;
    printf("[DEBUG] Current root block: %p\n", curr);

    // Refill the slab allocator if needed
    slab_refill_check(&(state->slab_allocator));
    printf("[DEBUG] Slab allocator checked and refilled if needed.\n");

    // Allocate a new block from the slab
    curr = slab_alloc(&(state->slab_allocator));
    if (curr == NULL) {
        printf("[ERROR] Slab allocation failed for a new block.\n");
        return NULL;
    }
    printf("[DEBUG] Allocated new block: %p\n", curr);

    // Allocate a frame for the requested bytes
    struct capref cap;
    errval_t err = frame_alloc(&cap, bytes, NULL);
    if (err_is_fail(err)) {
        printf("[ERROR] Frame allocation failed for %zu bytes: %s\n", bytes, err_getstring(err));
        return NULL;
    }
    printf("[DEBUG] Allocated frame: %zu bytes, cap: %p\n", bytes, (void *)&cap);

    // Map the frame into the virtual address space
    err = paging_map_frame_attr_offset(
        get_current_paging_state(), 
        (void **)(&curr->vaddr), 
        bytes, 
        cap, 
        0, 
        VREGION_FLAGS_READ_WRITE
    );
    if (err_is_fail(err)) {
        printf("[ERROR] Paging map failed for frame: %s\n", err_getstring(err));
        return NULL;
    }
    printf("[DEBUG] Mapped frame at virtual address: %p\n", (void *)curr->vaddr);

    // Set up the block metadata
    curr->next = NULL;
    *retbytes = bytes;
    printf("[DEBUG] Block setup complete. Virtual address: %p, Size: %zu bytes\n", (void *)curr->vaddr, bytes);

    return (void *)(curr->vaddr);

}

/**
 * @brief Frees memory that has been previously allocated by `morecore_alloc`
 *
 * @param[in] base   Virtual address of the region to be freed
 * @param[in] bytes  Size of the region to be freed
 */
static void morecore_free(void *base, size_t bytes)
{
    // struct morecore_state *state = get_morecore_state();
    // struct allocated_region *prev = NULL;
    // struct allocated_region *curr = state->allocated_list;

    // // Find the allocated region in the list
    // while (curr != NULL) {
    //     if (curr->base == base && curr->size == bytes) {
    //         break;
    //     }
    //     prev = curr;
    //     curr = curr->next;
    // }

    // // If the region is not found, panic
    // if (curr == NULL) {
    //     USER_PANIC("Attempted to free unallocated or mismatched region: %p\n", base);
    //     return;
    // }

    // // Unmap the memory region
    // errval_t err = paging_unmap(get_current_paging_state(), base);
    // if (err_is_fail(err)) {
    //     USER_PANIC("Failed to unmap memory: %s\n", err_getstring(err));
    //     return;
    // }

    // // Add the freed memory back to the free list
    // //err = add_to_free_list(get_current_paging_state(), (lvaddr_t)base, bytes);
    // if (err_is_fail(err)) {
    //     USER_PANIC("Failed to add freed region back to free list\n");
    //     return;
    // }

    // // Remove the region from the allocated list
    // if (prev == NULL) {
    //     state->allocated_list = curr->next;
    // } else {
    //     prev->next = curr->next;
    // }

    // // Free the allocated_region structure
    // slab_free(&state->slab_allocator, curr);

    // debug_printf("Successfully freed memory region [%p - %p]\n", base, (char *)base + bytes);

     (void)base;
    (void)bytes;
    struct morecore_state *state = get_morecore_state();
    struct allocdBlock * curr = state->root;
    struct allocdBlock * prev = curr;
    while (curr != NULL) {
        if (curr->vaddr == (lvaddr_t)base) {
            paging_unmap(get_current_paging_state(),base);
            prev->next = curr->next;
            // printf("found it!\n");
            //TODO: slab free curr
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    // printf("never found it\n");
    return;
}

/**
 * @brief initializes the morecore memory allocator backed with dynamically allocated memory
 *
 * @param[in] alignment  requested minimum alignment of the heap pages (mininum BASE_PAGE_SIZE)
 *
 * @return SYS_ERR_OK on success, error value on failure
 */
errval_t morecore_init(size_t alignment)
{
    // make compiler happy about unused parameters

    // struct morecore_state *state = get_morecore_state();

    // debug_printf("initializing static heap\n");

    // thread_mutex_init(&state->mutex);

    // static char initial_slab_buffer[100 * 20480];
    // slab_init(&state->slab_allocator, sizeof(struct page_table), NULL);
    // slab_grow(&state->slab_allocator, initial_slab_buffer, sizeof(initial_slab_buffer));

    // state->alignment = alignment;
    // state->allocated_list = NULL;

    // sys_morecore_alloc = morecore_alloc;
    // sys_morecore_free = morecore_free;
    // return SYS_ERR_OK;
     struct morecore_state *state = get_morecore_state();

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;

    slab_init(&state->slab_allocator, sizeof(struct allocdBlock), NULL);
    slab_grow(&state->slab_allocator, state->slab_buf, SLAB_STATIC_SIZE(NUM_MEM_BLOCKS_ALLOC, sizeof(struct allocdBlock)));
    state->root = NULL;
    state->alignment = alignment;

    return SYS_ERR_OK;
}

#endif /* !USE_STATIC_HEAP */

Header *get_malloc_freep(void);
Header *get_malloc_freep(void)
{
    return get_morecore_state()->header_freep;
}
