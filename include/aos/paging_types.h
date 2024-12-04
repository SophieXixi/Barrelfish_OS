/**
 * \file
 * \brief PMAP Implementaiton for AOS
 */

/*
 * Copyright (c) 2019 ETH Zurich.
 * Copyright (c) 2022 The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef PAGING_TYPES_H_
#define PAGING_TYPES_H_ 1

#include <aos/solution.h>

#define VADDR_OFFSET ((lvaddr_t)512UL*1024*1024*1024) // 1GB
#define VREGION_FLAGS_READ       0x01 // Reading allowed
#define VREGION_FLAGS_WRITE      0x02 // Writing allowed
#define VREGION_FLAGS_EXECUTE    0x04 // Execute allowed
#define VREGION_FLAGS_NOCACHE    0x08 // Caching disabled
#define VREGION_FLAGS_MPB        0x10 // Message passing buffer
#define VREGION_FLAGS_GUARD      0x20 // Guard page
#define VREGION_FLAGS_LARGE_PAGE 0x40 // Large page mapping
#define VREGION_FLAGS_MASK       0x7f // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)



typedef int paging_flags_t;

#define NUM_PT_SLOTS 512
#define NUM_PTS_ALLOC 2048
#define VADDR_CALCULATE(L0, L1, L2, L3, offset)                                                    \
    (offset) + (((int64_t)(L3)) << 12) + (((int64_t)(L2)) << 21) + (((int64_t)(L1)) << 30) + (((int64_t)(L0)) << 39);

struct page_table {
    uint64_t numFree;
    struct page_table *parent;
    struct capref mapping;
    struct capref self;
    size_t offset;
    size_t numBytes;
    struct page_table * children[NUM_PT_SLOTS];
};

/// struct to store the paging state of a process' virtual address space.
struct paging_state {
    /// slot allocator to be used for this paging state
    struct slot_allocator *slot_alloc;
    lvaddr_t start_vaddr;
    lvaddr_t current_vaddr;
    struct slab_allocator slab_allocator;
    struct page_table *root;
     char slab_buf[SLAB_STATIC_SIZE(NUM_PTS_ALLOC, sizeof(struct page_table))];
    
    // int add_slot;
    // int curr_slot;
    //struct paging_region *region_list;
    //struct paging_region *free_list;
    //struct mapped_region *mapped_list; 
    // struct thread_mutex paging_mutex;
    // struct thread_mutex heap_mutex;


    /// virtual address from which to allocate from.
    /// TODO(M2): replace me with proper region management
};


#endif  /// PAGING_TYPES_H_