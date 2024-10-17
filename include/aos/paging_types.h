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

struct page_table_entry {
    struct capref mapping;      // mapping capref
    struct page_table *next_level;
};

struct page_table {
    struct page_table_entry *pte[VMSAv8_64_PTABLE_NUM_ENTRIES];
    struct capref cap;          // the capref of the table
};

struct pgtb_entry {
    bool meta_data;
    lvaddr_t start_addr;            // when meta_data = false;
    size_t num_page;                    // when meta_data = false;
    struct capref next_level_pt;    // when meta_data = true; capref of children
    struct capref mapping;          
    struct pgtb *children;// when meta_data = true;
};

struct pgtb{
    struct pgtb_entry *pgtb_entry[VMSAv8_64_PTABLE_NUM_ENTRIES];
    struct pgtb *parent;
};

/// struct to store the paging state of a process' virtual address space.
struct paging_state {
    /// slot allocator to be used for this paging state
    lvaddr_t start_vaddr;
    struct slot_allocator *slot_alloc;
    struct slab_allocator slab_allocator;
    struct pgtb *meta_pt;
    struct capref root;
    struct page_table *l0;
    /// virtual address from which to allocate from.
    /// TODO(M2): replace me with proper region management
};


#endif  /// PAGING_TYPES_H_
