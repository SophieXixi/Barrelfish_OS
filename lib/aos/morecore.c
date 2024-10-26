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
#define USE_STATIC_HEAP


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
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    // make compiler happy about unused parameters
    (void)bytes;
    (void)retbytes;

    USER_PANIC("NYI: implement me\n");
    return NULL;
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

    USER_PANIC("NYI: implement me\n");
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
    (void)alignment;
    USER_PANIC("NYI: implement me\n");
    return LIB_ERR_NOT_IMPLEMENTED;
}

#endif /* !USE_STATIC_HEAP */

Header *get_malloc_freep(void);
Header *get_malloc_freep(void)
{
    return get_morecore_state()->header_freep;
}
