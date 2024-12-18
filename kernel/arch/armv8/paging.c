/*
 * Copyright (c) 2009-2012,2015,2016 ETH Zurich.
 * Copyright (c) 2015, Hewlett Packard Enterprise Development LP.
 * Copyright (c) 2022, The University of British Columbia
 *
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <kernel.h>
#include <dispatch.h>
#include <sysreg.h>
#include <paging_kernel_arch.h>
#include <string.h>
#include <exceptions.h>
#include <arm_hal.h>
#include <cap_predicates.h>
#include <dispatch.h>
#include <mdb/mdb_tree.h>
#include <dev/armv8_dev.h>
#include <useraccess.h>


// ------------------------------------------------------------------------
// Utility declarations

inline static uintptr_t paging_round_down(uintptr_t address, uintptr_t size)
{
    return address & ~(size - 1);
}

inline static uintptr_t paging_round_up(uintptr_t address, uintptr_t size)
{
    return (address + size - 1) & ~(size - 1);
}

inline static int aligned(uintptr_t address, uintptr_t bytes)
{
    return (address & (bytes - 1)) == 0;
}

static void
paging_write_l0_entry(union armv8_ttable_entry *l0_table, lvaddr_t va, union armv8_ttable_entry l0)
{
    assert(l0_table);
//    union armv8_l0_entry *l0_table;
//    if (ttbase == 0) {
//        if(va < MEMORY_OFFSET)
//            ttbase = sysreg_read_ttbr0_el1() + MEMORY_OFFSET;
//        else
//            ttbase = sysreg_read_ttbr1_el1() + MEMORY_OFFSET;
//    }
//    l0_table = (union armv8_l0_entry *) ttbase;

    l0_table[VMSAv8_64_L0_INDEX(va)] = l0;
}

static void
paging_write_l1_entry(union armv8_ttable_entry *l1_table, lvaddr_t va, union armv8_ttable_entry l1)
{
    assert(l1_table);
//    union armv8_l1_entry *l1_table;
//    if (ttbase == 0) {
//        if(va < MEMORY_OFFSET)
//            ttbase = sysreg_read_ttbr0_el1() + MEMORY_OFFSET;
//        else
//            ttbase = sysreg_read_ttbr1_el1() + MEMORY_OFFSET;
//    }
//    l1_table = (union armv8_l1_entry *) ttbase;

    l1_table[VMSAv8_64_L1_INDEX(va)] = l1;
}

static void
paging_write_l2_entry(union armv8_ttable_entry *l2_table, lvaddr_t va, union armv8_ttable_entry l2)
{
    assert(l2_table);
    l2_table[VMSAv8_64_L2_INDEX(va)] = l2;
}

static void
paging_write_l3_entry(union armv8_ttable_entry *l3_table, lvaddr_t va, union armv8_ttable_entry l3)
{
    assert(l3_table);
    l3_table[VMSAv8_64_L3_INDEX(va)] = l3;
}

// ------------------------------------------------------------------------
// Exported functions


/**
 * \brief Return whether we have enabled the MMU. Useful for
 * initialization assertions
 */
bool paging_mmu_enabled(void)
{
    return true;
}

void paging_map_kernel_section(union armv8_ttable_entry *ttbase, lvaddr_t va, lpaddr_t pa)
{
    union armv8_ttable_entry l2;

    l2.raw = 0;
    l2.block_l2.valid = 1;
    l2.block_l2.mb0 = 0;
    l2.block_l2.af = 1;
    l2.block_l2.base = pa >> 21u;
    paging_write_l2_entry(ttbase, va, l2);
}

void paging_map_kernel_l1_block(union armv8_ttable_entry *ttbase, lvaddr_t va, lpaddr_t pa)
{
    union armv8_ttable_entry l1;

    l1.raw = 0;
    l1.block_l1.valid = 1;
    l1.block_l1.mb0 = 0;
    l1.block_l1.af = 1;
    l1.block_l1.base = pa >> 30u;
    paging_write_l1_entry(ttbase, va, l1);
}

void paging_map_memory(union armv8_ttable_entry *ttbase, lpaddr_t paddr, size_t bytes)
{
    lpaddr_t pend  = paging_round_up(paddr + bytes, VMSAv8_64_L1_BLOCK_SIZE);
    while (paddr < pend) {
        paging_map_kernel_l1_block(ttbase,
                (paddr + MEMORY_OFFSET) - KERNEL_OFFSET,
                paddr);
        paddr += VMSAv8_64_L1_BLOCK_SIZE;
    }
}

//static lvaddr_t dev_alloc;

void paging_map_table_l0(union armv8_ttable_entry *table_base, lvaddr_t va, lpaddr_t pa)
{
    assert(aligned((uintptr_t)table_base, VMSAv8_64_PTABLE_SIZE));
    assert(aligned(pa, VMSAv8_64_PTABLE_SIZE));

    union armv8_ttable_entry e;

    e.raw = 0;
    e.d.valid = 1;
    e.d.mb1 = 1;
    e.d.base = (pa >> BASE_PAGE_BITS);

    paging_write_l0_entry(table_base, va, e);
}

void paging_map_table_l1(union armv8_ttable_entry *table_base, lvaddr_t va, lpaddr_t pa)
{
    assert(aligned((uintptr_t)table_base, VMSAv8_64_PTABLE_SIZE));
    assert(aligned(pa, VMSAv8_64_PTABLE_SIZE));

    union armv8_ttable_entry e;

    e.raw = 0;
    e.d.valid = 1;
    e.d.mb1 = 1;
    e.d.base = (pa >> BASE_PAGE_BITS);

    paging_write_l1_entry(table_base, va, e);
}

void paging_map_block_l1(union armv8_ttable_entry *table_base, lvaddr_t va, lpaddr_t pa, uintptr_t flags)
{
    assert(aligned((uintptr_t)table_base, VMSAv8_64_PTABLE_SIZE));
    assert(aligned(pa, VMSAv8_64_PTABLE_SIZE));

    union armv8_ttable_entry e;

    e.raw = flags;
    e.block_l1.valid = 1;
    e.block_l1.mb0 = 0;
    e.block_l1.af = 1;
    e.block_l1.base = (pa >> BASE_PAGE_BITS);

    paging_write_l1_entry(table_base, va, e);
}


void paging_map_table_l2(union armv8_ttable_entry *table_base, lvaddr_t va, lpaddr_t pa)
{
    assert(aligned((uintptr_t)table_base, VMSAv8_64_PTABLE_SIZE));
    assert(aligned(pa, VMSAv8_64_PTABLE_SIZE));
    assert(pa);

    union armv8_ttable_entry e;

    e.raw = 0;
    e.d.valid = 1;
    e.d.mb1 = 1;
    e.d.base = (pa >> BASE_PAGE_BITS);

//    printf("map table l2@%p->l3@%p\n", table_base + VMSAv8_64_L2_INDEX(va), pa);

    paging_write_l2_entry(table_base, va, e);
}

void paging_map_page_l3(union armv8_ttable_entry *table_base, lvaddr_t va, lpaddr_t pa, uintptr_t flags)
{
    assert(aligned((uintptr_t)table_base, VMSAv8_64_PTABLE_SIZE));
    assert(aligned(pa, VMSAv8_64_PTABLE_SIZE));

    assert(0 == (flags & 0xfffff000));
    assert(0 == (flags & 0x3));
    assert(0 == (pa & 0xfff));

    union armv8_ttable_entry e;
    e.raw = flags;

    e.page.valid = 1;
    e.page.mb1 = 1;
    e.page.af= 1;
    e.page.base = (pa >> BASE_PAGE_BITS);

    paging_write_l3_entry(table_base, va, e);
}

void paging_set_l3_entry(union armv8_ttable_entry *l3_entry, lpaddr_t pa, uintptr_t flags)
{
    assert(0 == (flags & 0xfffff000));
    assert(0 == (flags & 0x3));
    assert(0 == (pa & 0xfff));


    union armv8_ttable_entry e;
    e.raw = flags;

    e.page.valid = 1;
    e.page.mb1 = 1;
    e.page.af= 1;
    e.page.base = (pa >> BASE_PAGE_BITS);

//    printf("Setting l3 entry@%p -> (%p) %p raw: %p\n", l3_entry, e.page.base, e.page.base << BASE_PAGE_BITS, e.raw);

    *l3_entry = e;
}


//void paging_set_l2_entry(union armv8_ttable_entry *l2e, lpaddr_t addr, uintptr_t flags)
//{
//    assert(0 == (flags & 0xfffff000));
//    assert(0 == (flags & 0x3));
//    assert(0 == (addr & 0xfff));
//
//    union armv8_ttable_entry e;
//    e.raw = flags;
//
//    e.d.valid = 1;
//    e.d.mb1 = 1;
//    e.d.base = (addr >> 12);
//
//    *l2e = e;
//}
//
//void paging_set_l3_entry(union armv8_ttable_entry *l3e, lpaddr_t addr, uintptr_t flags)
//{
//    assert(0 == (flags & 0xfffff000));
//    assert(0 == (flags & 0x3));
//    assert(0 == (addr & 0xfff));
//
//    union armv8_ttable_entry e;
//    e.raw = flags;
//
//    e.page.valid = 1;
//    e.page.mb1 = 1;
//    e.page.af         = 1;
//    e.page.base = (addr >> 12);
//
//    *l3e = e;
//}


static void
paging_set_flags(union armv8_ttable_entry *entry, uintptr_t kpi_paging_flags)
{
    entry->page.sh = 3;

    if (kpi_paging_flags & KPI_PAGING_FLAGS_NOCACHE) {
        entry->page.attrindex = 1;
    } else {
        entry->page.attrindex = 0;
    }

    // AP  Unprivileged (EL0)  Privileged (EL1/2/3)
    // 00  No access           Read and write
    // 01  Read and write      Read and write
    // 10  No access           Read-only
    // 11  Read-only           Read-only

    if (kpi_paging_flags & KPI_PAGING_FLAGS_WRITE) {
        // Note, we can't set it to write-only, so we map it read-write
        entry->page.ap = 1;
    } else if (kpi_paging_flags & KPI_PAGING_FLAGS_READ) {
        // map it read-only for user and kernel
        entry->page.ap = 3;
    } else {
        // not writable and not readable, we map it no access for user, and read-write for kernel
        entry->page.ap = 0;
    }

    // set the user non-execute bit if it's not executable
    if (!(kpi_paging_flags & KPI_PAGING_FLAGS_EXECUTE)) {
        entry->page.uxn = 1;
    } else {
        entry->page.uxn = 0;
    }

    // set the page to be non-executable in kernel
    entry->page.pxn = 1;

    // mark it as accessed, so we don't trigger a page fault when software tries to access it
    entry->page.af = 1;
}

static errval_t
caps_map_l0(struct capability* dest,
            cslot_t            slot,
            struct capability* src,
            uintptr_t          kpi_paging_flags,
            uintptr_t          offset,
            uintptr_t          pte_count,
            struct cte*        mapping_cte)
{
    printf("CHOSE L0");
    (void)kpi_paging_flags;

    if (slot >= VMSAv8_64_PTABLE_NUM_ENTRIES) {
        debug(SUBSYS_PAGING, "slot = %"PRIuCSLOT"\n",slot);
        return SYS_ERR_VNODE_SLOT_INVALID;
    }

    if (pte_count != 1) {
        debug(SUBSYS_PAGING, "pte_count = %zu\n",(size_t)pte_count);
        return SYS_ERR_VM_MAP_SIZE;
    }


    if (src->type != ObjType_VNode_AARCH64_l1) {
        char buf[128];
        sprint_cap(buf, 128, src);
        debug(SUBSYS_PAGING, "src: %s\n", buf);
        printf("Unexpected src type: %d (Expected: %d)\n", src->type, ObjType_VNode_AARCH64_l1);
        return SYS_ERR_WRONG_MAPPING;
    }

    // Destination
    lpaddr_t dest_lpaddr = gen_phys_to_local_phys(get_address(dest));
    lvaddr_t dest_lvaddr = local_phys_to_mem(dest_lpaddr);

    union armv8_ttable_entry* entry = (union armv8_ttable_entry*) dest_lvaddr + slot;

    // Source
    genpaddr_t src_gpaddr = get_address(src);
    lpaddr_t   src_lpaddr = gen_phys_to_local_phys(src_gpaddr);

    //union armv8_l2_entry* entry1 = (union armv8_l2_entry*)local_phys_to_mem(src_gpaddr);


    assert(offset == 0);
    assert(aligned(src_lpaddr, 1u << 12));
    assert((src_lpaddr < dest_lpaddr) || (src_lpaddr >= dest_lpaddr + 32));

    if (entry->d.valid) {
        // cleanup mapping info
        debug(SUBSYS_PAGING, "slot in use\n");
        return SYS_ERR_VNODE_SLOT_INUSE;
    }

    create_mapping_cap(mapping_cte, src, cte_for_cap(dest), slot, pte_count);

    entry->raw = 0;
    entry->d.valid = 1;
    entry->d.mb1 = 1;
    entry->d.base = (src_lpaddr) >> 12;
    debug(SUBSYS_PAGING, "L0 mapping %"PRIuCSLOT". @%p = %08"PRIx32"\n",
              slot, entry, entry->raw);

    sysreg_invalidate_tlb();

    return SYS_ERR_OK;
}
static errval_t
caps_map_l1(struct capability* dest,
            cslot_t            slot,
            struct capability* src,
            uintptr_t          kpi_paging_flags,
            uintptr_t          offset,
            uintptr_t          pte_count,
            struct cte*        mapping_cte)
{
    printf("CHOSE L1");
    (void)kpi_paging_flags;

    if (slot >= VMSAv8_64_PTABLE_NUM_ENTRIES) {
        debug(SUBSYS_PAGING, "slot = %"PRIuCSLOT"\n",slot);
        return SYS_ERR_VNODE_SLOT_INVALID;
    }

    if (pte_count != 1) {
        debug(SUBSYS_PAGING, "pte_count = %zu\n",(size_t)pte_count);
        return SYS_ERR_VM_MAP_SIZE;
    }

    printf("Source type: %d, Destination type: %d\n", src->type, dest->type);
    if (src->type != ObjType_VNode_AARCH64_l2) {
        printf("Unexpected src type: %d (Expected: %d)\n", src->type, ObjType_VNode_AARCH64_l2);
        return SYS_ERR_WRONG_MAPPING;
    }

    if (slot >= VMSAv8_64_PTABLE_NUM_ENTRIES) {
        debug(SUBSYS_PAGING, "slot = %"PRIuCSLOT"\n",slot);
        return SYS_ERR_VNODE_SLOT_RESERVED;
    }

    // Destination
    lpaddr_t dest_lpaddr = gen_phys_to_local_phys(get_address(dest));
    lvaddr_t dest_lvaddr = local_phys_to_mem(dest_lpaddr);

    union armv8_ttable_entry* entry = (union armv8_ttable_entry*) dest_lvaddr + slot;

    // Source
    genpaddr_t src_gpaddr = get_address(src);
    lpaddr_t   src_lpaddr = gen_phys_to_local_phys(src_gpaddr);

	//union armv8_l2_entry* entry1 = (union armv8_l2_entry*)local_phys_to_mem(src_gpaddr);


    assert(offset == 0);
    assert(aligned(src_lpaddr, 1u << 12));
    assert((src_lpaddr < dest_lpaddr) || (src_lpaddr >= dest_lpaddr + 32));

    if (entry->d.valid) {
        // cleanup mapping info
        debug(SUBSYS_PAGING, "slot in use\n");
        return SYS_ERR_VNODE_SLOT_INUSE;
    }

    create_mapping_cap(mapping_cte, src, cte_for_cap(dest), slot, pte_count);

    entry->raw = 0;
    entry->d.valid = 1;
    entry->d.mb1 = 1;
    entry->d.base = (src_lpaddr) >> 12;
    debug(SUBSYS_PAGING, "L1 mapping %"PRIuCSLOT". @%p = %08"PRIx32"\n",
              slot, entry, entry->raw);

    sysreg_invalidate_tlb();

    return SYS_ERR_OK;
}


static errval_t caps_map_l2(struct capability *dest, cslot_t slot, struct capability *src,
                            uintptr_t kpi_paging_flags, uintptr_t offset,
                            uintptr_t pte_count, struct cte *mapping_cte)
{
    printf("CHOSE L2");
    printf("Source type: %d, Destination type: %d\n", src->type, dest->type);

    // make compiler happy about unused parameters
    (void)kpi_paging_flags;

    if (slot >= VMSAv8_64_PTABLE_NUM_ENTRIES) {
        debug(SUBSYS_PAGING, "slot = %" PRIuCSLOT "\n", slot);
        return SYS_ERR_VNODE_SLOT_INVALID;
    }

    // Destination
    lpaddr_t dest_lpaddr = gen_phys_to_local_phys(get_address(dest));
    lvaddr_t dest_lvaddr = local_phys_to_mem(dest_lpaddr);

    // source
    genpaddr_t src_gpaddr = get_address(src) + offset;
    lpaddr_t src_lpaddr = gen_phys_to_local_phys(src_gpaddr);

    union armv8_ttable_entry *entry = (union armv8_ttable_entry *)dest_lvaddr + slot;

    switch (src->type) {
    case ObjType_VNode_AARCH64_l3:
        if (pte_count != 1) {
            debug(SUBSYS_PAGING, "pte_count = %zu\n", (size_t)pte_count);
            return SYS_ERR_VM_MAP_SIZE;
        }
        if (offset != 0) {
            debug(SUBSYS_PAGING, "offset = %zu\n", (size_t)offset);
            return SYS_ERR_VM_MAP_OFFSET;
        }
        if (entry->d.valid) {
            // cleanup mapping info
            debug(SUBSYS_PAGING, "slot in use\n");
            return SYS_ERR_VNODE_SLOT_INUSE;
        }
        assert(offset == 0);
        assert(aligned(src_lpaddr, 1u << 12));
        assert((src_lpaddr < dest_lpaddr) || (src_lpaddr >= dest_lpaddr + 4096));

        entry->raw = 0;
        entry->d.valid = 1;
        entry->d.mb1 = 1;
        entry->d.base = (src_lpaddr) >> 12;
        debug(SUBSYS_PAGING, "L2 mapping %" PRIuCSLOT ". @%p = %08" PRIx32 "\n", slot,
              entry, entry->raw);

        break;
    default:
        printf("ERROR IN THIRD");
        return SYS_ERR_WRONG_MAPPING;
    }

    create_mapping_cap(mapping_cte, src, cte_for_cap(dest), slot, pte_count);

    sysreg_invalidate_tlb();

    return SYS_ERR_OK;
}


static errval_t
caps_map_l3(struct capability* dest,
            cslot_t            slot,
            struct capability* src,
            uintptr_t          kpi_paging_flags,
            uintptr_t          offset,
            uintptr_t          pte_count,
            struct cte*        mapping_cte)
{
    assert(0 == (kpi_paging_flags & ~KPI_PAGING_FLAGS_MASK));
    printf("CHOSE L3");
    printf("Source type: %d, Destination type: %d\n", src->type, dest->type);


    // Check slot is valid and mapping does not overlap leaf page table
    if (slot + pte_count > VMSAv8_64_PTABLE_NUM_ENTRIES) {
        if (slot >= VMSAv8_64_PTABLE_NUM_ENTRIES) {
            return SYS_ERR_VNODE_SLOT_INVALID;
        }
        else {
            return SYS_ERR_VM_MAP_SIZE;
        }
    }

    if (src->type != ObjType_Frame && src->type != ObjType_DevFrame) {
        printf("ERROR IN LAST");
        return SYS_ERR_WRONG_MAPPING;
    }

    // check offset within frame
    if ((offset + pte_count * BASE_PAGE_SIZE > get_size(src)) ||
        ((offset % BASE_PAGE_SIZE) != 0)) {
        return SYS_ERR_FRAME_OFFSET_INVALID;
    }

    // Destination
    lpaddr_t dest_lpaddr = gen_phys_to_local_phys(get_address(dest));
    lvaddr_t dest_lvaddr = local_phys_to_mem(dest_lpaddr);

    union armv8_ttable_entry *entry = (union armv8_ttable_entry *)dest_lvaddr + slot;
    //printf("Starting to map %zu page table entries at virtual address: 0x%lx\n", pte_count, (uintptr_t)dest_lvaddr);
    for (size_t i = 0; i < pte_count; i++) {
        if (entry[i].d.valid) {
            //printf("ARMv8 L3 @ 0x%lx: slot %zu already in use\n",
                        // (uintptr_t)dest_lvaddr, slot + i);
            return SYS_ERR_VNODE_SLOT_INUSE;
        } else {
            //printf("ARMv8 L3 @ 0x%lx: slot %zu available\n",
                        // (uintptr_t)dest_lvaddr, slot + i);
        }
    }
    uint64_t start_vaddr = dest_lvaddr + (slot * BASE_PAGE_SIZE);
    uint64_t end_vaddr = start_vaddr + (pte_count * BASE_PAGE_SIZE) - 1;

    printf("Mapping %zu pages from virtual address 0x%lx to 0x%lx\n", pte_count, start_vaddr, end_vaddr);


    lpaddr_t src_lpaddr = gen_phys_to_local_phys(get_address(src) + offset);
    if ((src_lpaddr & (BASE_PAGE_SIZE - 1))) {
        return SYS_ERR_VM_FRAME_UNALIGNED;
    }

    create_mapping_cap(mapping_cte, src, cte_for_cap(dest), slot, pte_count);

    for (size_t i = 0; i < pte_count; i++) {
        entry->raw = 0;

        entry->page.valid = 1;
        entry->page.mb1 = 1;
        paging_set_flags(entry, kpi_paging_flags);
        entry->page.base = (src_lpaddr + i * BASE_PAGE_SIZE) >> 12;

        debug(SUBSYS_PAGING, "L3 mapping %08"PRIxLVADDR"[%"PRIuCSLOT"] @%p = %08"PRIx64"\n",
               dest_lvaddr, slot, entry, entry->raw);

		entry++;

    }

    // Flush TLB if remapping.
    sysreg_invalidate_tlb();

    return SYS_ERR_OK;
}

typedef errval_t (*mapping_handler_t)(struct capability *dest_cap,
                                      cslot_t dest_slot,
                                      struct capability *src_cap,
                                      uintptr_t flags, uintptr_t offset,
                                      size_t pte_count,
                                      struct cte *mapping_cte);

/// Dispatcher table for the type of mapping to create
static mapping_handler_t handler[ObjType_Num] = {
        [ObjType_VNode_AARCH64_l0]   = caps_map_l0,
        [ObjType_VNode_AARCH64_l1]   = caps_map_l1,
        [ObjType_VNode_AARCH64_l2]   = caps_map_l2,
        [ObjType_VNode_AARCH64_l3]   = caps_map_l3,
};


/// Create page mappings
errval_t caps_copy_to_vnode(struct cte *dest_vnode_cte, cslot_t dest_slot,
                            struct cte *src_cte, uintptr_t flags,
                            uintptr_t offset, uintptr_t pte_count,
                            struct cte *mapping_cte)
{
    struct capability *src_cap  = &src_cte->cap;
    struct capability *dest_cap = &dest_vnode_cte->cap;
    assert(mapping_cte->cap.type == ObjType_Null);
    mapping_handler_t handler_func = handler[dest_cap->type];

    assert(handler_func != NULL);

    errval_t err;

    err = handler_func(dest_cap, dest_slot, src_cap, flags, offset, pte_count,
            mapping_cte);

    if (err_is_fail(err)) {
        assert(mapping_cte->cap.type == ObjType_Null);
        debug(SUBSYS_PAGING,
                "caps_copy_to_vnode: handler func returned %"PRIuERRV"\n", err);
        return err;
    }

    /* insert mapping cap into mdb */
    err = mdb_insert(mapping_cte);
    if (err_is_fail(err)) {
        printk(LOG_ERR, "%s: mdb_insert: %"PRIuERRV"\n", __FUNCTION__, err);
    }

    TRACE_CAP_MSG("created", mapping_cte);

    return err;
}

size_t do_unmap(lvaddr_t pt, cslot_t slot, size_t num_pages)
{
    size_t unmapped_pages = 0;
    union armv8_ttable_entry *ptentry = (union armv8_ttable_entry *)pt + slot;
    for (size_t i = 0; i < num_pages; i++) {
        ptentry++->raw = 0;
        unmapped_pages++;
    }
    return unmapped_pages;
}

errval_t paging_modify_flags(struct capability *mapping, uintptr_t offset,
                             uintptr_t pages, uintptr_t kpi_paging_flags)
{
    assert(type_is_mapping(mapping->type));
    struct Frame_Mapping *info = &mapping->u.frame_mapping;

    // check flags
    assert(0 == (kpi_paging_flags & ~KPI_PAGING_FLAGS_MASK));

    /* Calculate location of page table entries we need to modify */
    lvaddr_t base = local_phys_to_mem(get_address(&info->ptable->cap)) +
        (info->entry + offset) * sizeof(union armv8_ttable_entry *);

    for (size_t i = 0; i < pages; i++) {
        union armv8_ttable_entry *entry =
            (union armv8_ttable_entry *)base + i;
        paging_set_flags(entry, kpi_paging_flags);
    }

    return paging_tlb_flush_range(cte_for_cap(mapping), 0, pages);
}

errval_t paging_copy_remap(struct cte *dest_vnode_cte, cslot_t dest_slot,
                           struct cte *src_cte, uintptr_t flags,
                           uintptr_t offset, uintptr_t pte_count,
                           struct cte *mapping_cte)
{
    (void) dest_vnode_cte;
    (void) dest_slot;
    (void) src_cte;
    (void) flags;
    (void) offset;
    (void) pte_count;
    (void) mapping_cte;

    printk(LOG_ERR, "%s called on ARMv8: NYI!\n", __FUNCTION__);
    return SYS_ERR_NOT_IMPLEMENTED;
}

bool paging_is_region_valid(lvaddr_t buffer, size_t size, uint8_t type)
{
    (void) type;
    // XXX: ARMv8 does not seem to have ro mappings? -SG,2018-10-25.
    // this currently ignores type
    lvaddr_t root_pt = local_phys_to_mem(dcb_current->vspace);

    lvaddr_t end = buffer + size;

    uint16_t first_l0idx = VMSAv8_64_L0_INDEX(buffer);
    uint16_t last_l0idx = VMSAv8_64_L0_INDEX(end);

    uint16_t first_l1idx, first_l2idx, first_l3idx;
    uint16_t last_l1idx, last_l2idx, last_l3idx;


    union armv8_ttable_entry *pte;

    for (uint16_t l0idx = first_l0idx; l0idx <= last_l0idx; l0idx++) {
        pte = (union armv8_ttable_entry *)root_pt + l0idx;
        if (!pte->d.valid) { return false; }
        // calculate which part of pdpt to check
        first_l1idx = l0idx == first_l0idx ? VMSAv8_64_L1_INDEX(buffer) : 0;
        last_l1idx  = l0idx == last_l0idx  ? VMSAv8_64_L1_INDEX(end)  : PTABLE_ENTRIES;
        // read pdpt base
        lvaddr_t pdpt = local_phys_to_mem((genpaddr_t)pte->d.base << BASE_PAGE_BITS);
        for (uint16_t l1idx = first_l1idx; l1idx <= last_l1idx; l1idx++) {
            pte = (union armv8_ttable_entry *)pdpt + l1idx;
            if (!pte->d.valid) { return false; }
            // calculate which part of pdpt to check
            first_l2idx = l1idx == first_l1idx ? VMSAv8_64_L2_INDEX(buffer) : 0;
            last_l2idx  = l1idx == last_l1idx  ? VMSAv8_64_L2_INDEX(end)  : PTABLE_ENTRIES;
            // read pdpt base
            lvaddr_t pdir = local_phys_to_mem((genpaddr_t)pte->d.base << BASE_PAGE_BITS);
            for (uint16_t l2idx = first_l2idx; l2idx <= last_l2idx; l2idx++) {
                pte = (union armv8_ttable_entry *)pdir + l2idx;
                if (!pte->d.valid) { return false; }
                // calculate which part of pdpt to check
                first_l3idx = l2idx == first_l2idx ? VMSAv8_64_L3_INDEX(buffer) : 0;
                last_l3idx  = l2idx == last_l2idx  ? VMSAv8_64_L3_INDEX(end)  : PTABLE_ENTRIES;
                // read pdpt base
                lvaddr_t pt = local_phys_to_mem((genpaddr_t)pte->d.base << BASE_PAGE_BITS);
                for (uint16_t l3idx = first_l3idx; l3idx < last_l3idx; l3idx++) {
                    pte = (union armv8_ttable_entry *)pt + l3idx;
                    if (!pte->page.valid) { return false; }
                }
            }
        }
    }
    // if we never bailed early, the access is fine.
    return true;
}

void paging_dump_tables(struct dcb *dispatcher, lvaddr_t addr)
{
    if (!local_phys_is_valid(dispatcher->vspace)) {
        printk(LOG_ERR, "dispatcher->vspace = 0x%"PRIxLPADDR": too high!\n" ,
               dispatcher->vspace);
        return;
    }
    lvaddr_t l0 = local_phys_to_mem(dispatcher->vspace);

    if (addr < (VMSAv8_64_PTABLE_NUM_ENTRIES * VMSAv8_64_PTABLE_NUM_ENTRIES * HUGE_PAGE_SIZE)) {
        uint32_t l0_index = VMSAv8_64_L0_INDEX(addr);
        uint32_t l1_index = VMSAv8_64_L1_INDEX(addr);
        uint32_t l2_index = VMSAv8_64_L2_INDEX(addr);
        uint32_t l3_index = VMSAv8_64_L3_INDEX(addr);

        printf("dumping table: %lx -> %u.%u.%u.%u\n", addr, l0_index, l1_index, l2_index, l3_index);

        union armv8_ttable_entry *l0_e = (union armv8_ttable_entry *) l0 + l0_index;
        if (!l0_e->d.valid) {
            printf("l0[% 3d] -> INVALID\n", l0_index);
            return;
        }

        genpaddr_t l1_gp = (genpaddr_t)(l0_e->d.base) << BASE_PAGE_BITS;
        lvaddr_t l1 = local_phys_to_mem(gen_phys_to_local_phys(l1_gp));
        printf("l0[% 3d] -> l1 @ %p\n", l0_index, l1);

        union armv8_ttable_entry *l1_e = (union armv8_ttable_entry *)l1 + l1_index;
        if (!l1_e->d.valid) {
            printf("  l1[% 3d] -> INVALID\n", l1_index);
            return;
        }

        // super page mapping
        if (l1_e->block_l1.mb0 == 0) {
            genpaddr_t l2_gp = (genpaddr_t)(l1_e->block_l1.base) << HUGE_PAGE_BITS;
            printf("  l1[% 3d] -> HUGE_PAGE @ 0x%lx\n", l1_index, l2_gp);
            return;
        }

        genpaddr_t l2_gp = (genpaddr_t)(l1_e->d.base) << BASE_PAGE_BITS;
        lvaddr_t l2 = local_phys_to_mem(gen_phys_to_local_phys(l2_gp));
        printf("  l1[% 3d] -> l2 @ %p\n", l1_index, l2);

        union armv8_ttable_entry *l2_e = (union armv8_ttable_entry *)l2 + l2_index;
        if (!l2_e->d.valid) {
            printf("    l2[% 3d] -> INVALID\n", l2_index);
            return;
        }

         if (l2_e->block_l2.mb0 == 0) {
            genpaddr_t l3_gp = ((genpaddr_t)(l2_e->block_l2.base)) << LARGE_PAGE_BITS;
            printf("    l2[% 3d] -> LARGE_PAGE @ 0x%lx (%lx)\n", l2_index, l3_gp, l2_e->raw);
            return;
         }

        genpaddr_t l3_gp = (genpaddr_t)(l2_e->d.base) << BASE_PAGE_BITS;
        lvaddr_t l3 = local_phys_to_mem(gen_phys_to_local_phys(l3_gp));
        printf("    l2 [% 3d] -> l3 @ %p\n", l2_index, l3);

        union armv8_ttable_entry *l3_e = (union armv8_ttable_entry *)l3 + l3_index;
        if (!l3_e->d.valid) {
            printf("      l3[% 3d] -> INVALID\n", l3_index);
            return;
        }
        genpaddr_t paddr = (genpaddr_t)(l3_e->page.base) << BASE_PAGE_BITS;
        printf("      l3[% 3d] -> BASE_PAGE @ 0x%lx \n", l3_index, paddr);

        return;
    }

    for (unsigned l0_index = 0; l0_index < VMSAv8_64_PTABLE_NUM_ENTRIES; l0_index++) {
        // get level0 table
        union armv8_ttable_entry *l0_e = (union armv8_ttable_entry *) l0 + l0_index;
        if (!l0_e->raw) {
            continue;
        }
        genpaddr_t l1_gp = (genpaddr_t)(l0_e->d.base) << BASE_PAGE_BITS;
        lvaddr_t l1 = local_phys_to_mem(gen_phys_to_local_phys(l1_gp));
        printf("l0 %d -> %p\n", l0_index, l1);

        for (unsigned l1_index = 0; l1_index < VMSAv8_64_PTABLE_NUM_ENTRIES; l1_index++) {
            // get level1 table
            union armv8_ttable_entry *l1_e = (union armv8_ttable_entry *)l1 + l1_index;
            if (!l1_e->raw) { continue; }
            genpaddr_t l2_gp = (genpaddr_t)(l1_e->d.base) << BASE_PAGE_BITS;
            lvaddr_t l2 = local_phys_to_mem(gen_phys_to_local_phys(l2_gp));
            printf("  l1 %d -> %p\n", l1_index, l2);

            for (unsigned l2_index = 0; l2_index < VMSAv8_64_PTABLE_NUM_ENTRIES; l2_index++) {
                // get level2 table
                union armv8_ttable_entry *l2_e = (union armv8_ttable_entry *)l2 + l2_index;
                if (!l2_e->raw) { continue; }
                genpaddr_t l3_gp = (genpaddr_t)(l2_e->d.base) << BASE_PAGE_BITS;
                lvaddr_t l3 = local_phys_to_mem(gen_phys_to_local_phys(l3_gp));
                printf("    l2 %d -> %p\n", l2_index, l3);

                for (unsigned entry = 0; entry < VMSAv8_64_PTABLE_NUM_ENTRIES; entry++) {
                    union armv8_ttable_entry *e =
                        (union armv8_ttable_entry *)l3 + entry;
                    genpaddr_t paddr = (genpaddr_t)(e->page.base) << BASE_PAGE_BITS;
                    if (!paddr) {
                        continue;
                    }
                    printf("%d.%d.%d.%d: 0x%"PRIxGENPADDR" \n", l0_index, l1_index, l2_index, entry, paddr);
                }
            }
        }
    }
}

/* XXX - rewrite this. */
void paging_context_switch(lpaddr_t ttbr)
{
    assert(ttbr < MEMORY_OFFSET);
    //assert((ttbr & 0x3fff) == 0);

    lpaddr_t old_ttbr = armv8_TTBR0_EL1_rd(NULL);
    if (ttbr != old_ttbr)
    {
        armv8_TTBR0_EL1_wr(NULL, ttbr);
        sysreg_invalidate_tlb();
        //this isn't necessary on gem5, since gem5 doesn't implement the cache
        //maintenance instructions, but ensures coherency by itself
        //sysreg_invalidate_i_and_d_caches();
    }
}
