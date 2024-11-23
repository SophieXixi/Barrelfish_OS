#include <string.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>

#include "coreboot.h"


#define ARMv8_KERNEL_OFFSET 0xffff000000000000

#define NEW_CORE_MEM_SZ 1024 * 1024 * 256     // 256 mib

extern struct platform_info platform_info;
extern struct bootinfo     *bi;
const char *global_cpu_driver;
const char *global_init;

extern genvaddr_t global_urpc_frames[4];

struct mem_info {
    size_t   size;       // Size in bytes of the memory region
    void    *buf;        // Address where the region is currently mapped
    lpaddr_t phys_base;  // Physical base address
};

/**
 * Load a ELF image into memory.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF will be loaded
 * entry_point:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t load_elf_binary(genvaddr_t             binary,
                                                          const struct mem_info *mem,
                                                          genvaddr_t             entry_point,
                                                          genvaddr_t            *reloc_entry_point)

{
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point = 0;
    bool loaded            = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                         ", memory size 0x%" PRIx64 " SKIP\n",
                         i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64 ", memory size "
                     "0x%" PRIx64 " LO"
                     "AD"
                     "\n",
                     i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void    *dest      = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if (entry_point >= phdr[i].p_vaddr && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
                *reloc_entry_point = (dest_phys + (entry_point - phdr[i].p_vaddr));
                found_entry_point  = 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF is loaded
 * kernel_:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t relocate_elf(genvaddr_t binary, struct mem_info *mem,
                                                       lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t             shnum = ehdr->e_shnum;
    struct Elf64_Phdr *phdr  = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for (size_t i = 0; i < shnum; i++) {
        struct Elf64_Shdr *shdr = &shead[i];
        if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if (shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                             " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base  = phdr[0].p_vaddr;
            uint64_t segment_load_base = mem->phys_base;
            uint64_t segment_delta     = segment_load_base - segment_elf_base;
            uint64_t segment_vdelta    = (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if (shdr->sh_type == SHT_REL) {
                rsize = sizeof(struct Elf64_Rel);
            } else {
                rsize = sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel = shdr->sh_size / rsize;

            void *reldata = (void *)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for (size_t ii = 0; ii < nrel; ii++) {
                void *reladdr = reldata + ii * rsize;

                switch (shdr->sh_type) {
                case SHT_REL:
                    DEBUG_PRINTF("SHT_REL unimplemented.\n");
                    return ELF_ERR_PROGHDR;
                case SHT_RELA: {
                    struct Elf64_Rela *rel = reladdr;

                    uint64_t offset = rel->r_offset;
                    uint64_t sym    = ELF64_R_SYM(rel->r_info);
                    uint64_t type   = ELF64_R_TYPE(rel->r_info);
                    uint64_t addend = rel->r_addend;

                    uint64_t *rel_target = (void *)offset + segment_vdelta;

                    switch (type) {
                    case R_AARCH64_RELATIVE:
                        if (sym != 0) {
                            DEBUG_PRINTF("Relocation references a"
                                         " dynamic symbol, which is"
                                         " unsupported.\n");
                            return ELF_ERR_PROGHDR;
                        }

                        /* Delta(S) + A */
                        *rel_target = addend + segment_delta + load_offset;
                        break;

                    default:
                        DEBUG_PRINTF("Unsupported relocation type %d\n", type);
                        return ELF_ERR_PROGHDR;
                    }
                } break;
                default:
                    DEBUG_PRINTF("Unexpected type\n");
                    break;
                }
            }
        }
    }

    return SYS_ERR_OK;
}

static errval_t allocate_and_map_frame(struct capref *frame, size_t size, void **buf, uint64_t flags) {
    errval_t err = frame_alloc(frame, size, NULL);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate frame of size %zu\n", size);
        return err;
    }

    err = paging_map_frame_attr(get_current_paging_state(), buf, size, *frame, flags);
    if (err_is_fail(err)) {
        debug_printf("Couldn't map frame into virtual memory\n");
        return err;
    }
    return SYS_ERR_OK;
}

// Helper function to allocate RAM and identify its capability
static errval_t allocate_and_identify_ram(struct capref *ram, size_t size, struct capability *cap) {
    errval_t err = ram_alloc(ram, size);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate RAM of size %zu\n", size);
        return err;
    }

    err = cap_direct_identify(*ram, cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't identify RAM capability\n");
        return err;
    }
    return SYS_ERR_OK;
}

// Helper function to set up a memory region from a capability
static struct armv8_coredata_memreg setup_memory_region(struct capability cap) {
    struct armv8_coredata_memreg mem;
    mem.base = cap.u.ram.base;
    mem.length = cap.u.ram.bytes;
    return mem;
}

/**
 * @brief Allocates and retypes a KCB (Kernel Control Block) capability.
 *
 * @param[out] kcb_capref         Pointer to the slot where the KCB capability will be stored.
 * @param[out] kcb_ram_capability Pointer to the capability structure that will store the identified RAM capability.
 *
 * @return SYS_ERR_OK on success, or an error value on failure.
 */
static errval_t allocate_and_retype_kcb(struct capref *kcb_capref, struct capability *kcb_ram_capability) {
    errval_t err;

    // Step 1: Allocate aligned RAM for the KCB using helper function
    struct capref kcb_ram_capref;
    err = allocate_and_identify_ram(&kcb_ram_capref, OBJSIZE_KCB, kcb_ram_capability);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate and identify RAM for KCB\n");
        return err;
    }

    // Step 2: Allocate a slot for the KCB
    err = slot_alloc(kcb_capref);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate slot for KCB\n");
        return err;
    }

    // Step 3: Retype the allocated RAM capability into a KCB capability
    err = cap_retype(*kcb_capref, kcb_ram_capref, 0, ObjType_KernelControlBlock, OBJSIZE_KCB);
    if (err_is_fail(err)) {
        debug_printf("Couldn't retype RAM capability into KCB capability\n");
        return err;
    }

    // Debug output for the KCB's base address and size
    debug_printf("KCB base: %p, size: %lu\n", kcb_ram_capability->u.ram.base, kcb_ram_capability->u.ram.bytes);

    return SYS_ERR_OK;
}


/**
 * @brief Loads, maps, and relocates a driver ELF binary.
 *
 * @param[in]  driver_name          The name of the driver (e.g., "CPU driver" or "boot driver").
 * @param[in]  driver_path          Path to the driver binary.
 * @param[in]  entry_symbol         Entry point symbol name in the ELF binary.
 * @param[out] reloc_entry_point    Relocated entry point of the ELF binary.
 * @param[out] mi                   Memory info structure for the ELF binary.
 * @param[in]  relocation_offset    The offset for relocation (0 for boot driver, ARMV8_KERNEL_OFFSET for CPU driver).
 *
 * @return SYS_ERR_OK on success, or an error value on failure.
 */
static errval_t load_map_relocate_driver(const char *driver_name, const char *driver_path, 
                                         const char *entry_symbol, genvaddr_t *reloc_entry_point, 
                                         struct mem_info *mi, genvaddr_t relocation_offset) 
{
    errval_t err;

    // Find the driver module and get its frame
    struct mem_region *driver_mr = multiboot_find_module(bi, driver_path);
    if (driver_mr == NULL) {
        debug_printf("Couldn't find %s module\n", driver_name);
        return -1;
    }
    
    struct capref driver_frame = {
        .cnode = cnode_module,
        .slot = driver_mr->mrmod_slot,
    };

    // Get the size of the driver frame by identifying the capability
    struct capability driver_cap;
    err = cap_direct_identify(driver_frame, &driver_cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't identify frame for %s\n", driver_name);
        return err;
    }
    size_t driver_bytes = driver_cap.u.frame.bytes;

    // Map the driver frame
    void *driver_buf;
    err = paging_map_frame_attr(get_current_paging_state(), &driver_buf, driver_bytes, 
                                driver_frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        debug_printf("Couldn't map %s frame\n", driver_name);
        return err;
    }

    // Allocate and map a new frame for the ELF binary
    struct capref driver_elf_frame;
    void *driver_elf_buf;
    err = allocate_and_map_frame(&driver_elf_frame, driver_bytes, &driver_elf_buf, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate and map %s ELF frame\n", driver_name);
        return err;
    }

    // Identify the ELF frame capability and set up the memory info
    struct capability driver_elf_cap;
    err = cap_direct_identify(driver_elf_frame, &driver_elf_cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't identify %s ELF frame capability\n", driver_name);
        return err;
    }
    mi->buf = driver_elf_buf;
    mi->phys_base = driver_elf_cap.u.ram.base;
    mi->size = driver_bytes;

    // Get the physical entry point of the ELF binary
    struct Elf64_Sym *entry = elf64_find_symbol_by_name((genvaddr_t)driver_buf, driver_bytes, 
                                                        entry_symbol, 0, STT_FUNC, NULL);
    if (entry == NULL) {
        debug_printf("Couldn't find %s entry point symbol\n", entry_symbol);
        return -1;
    }
    genvaddr_t phys_entry_point = entry->st_value;

    // Load the ELF binary into the ELF binary frame
    err = load_elf_binary((genvaddr_t)driver_buf, mi, phys_entry_point, reloc_entry_point);
    if (err_is_fail(err)) {
        debug_printf("Couldn't load %s binary\n", driver_name);
        return err;
    }

    // Relocate the ELF binary
    err = relocate_elf((genvaddr_t)driver_buf, mi, relocation_offset);
    if (err_is_fail(err)) {
        debug_printf("Couldn't relocate %s\n", driver_name);
        return err;
    }

    return SYS_ERR_OK;
}



// Helper function to initialize the core data structure
static void initialize_core_data_struct(struct armv8_core_data *coreData, struct capability stack_cap,
                                        struct armv8_coredata_memreg initProcess_mem,
                                        struct armv8_coredata_memreg urpc_mem,
                                        struct armv8_coredata_memreg monitor_binary,
                                        genvaddr_t cpu_reloc_entry_point, coreid_t mpid,
                                        struct capability kcb_ram_capref) {
    coreData->boot_magic = ARMV8_BOOTMAGIC_PSCI;
    coreData->cpu_driver_stack = stack_cap.u.ram.base + stack_cap.u.ram.bytes;
    coreData->cpu_driver_stack_limit = stack_cap.u.ram.base;
    coreData->cpu_driver_entry = cpu_reloc_entry_point + ARMv8_KERNEL_OFFSET;
    memset(coreData->cpu_driver_cmdline, 0, sizeof(coreData->cpu_driver_cmdline));

    // Set memory regions
    coreData->memory = initProcess_mem;
    coreData->urpc_frame = urpc_mem;
    coreData->monitor_binary = monitor_binary;
    coreData->kcb = kcb_ram_capref.u.ram.base;

    // Set core and architecture identifiers
    coreData->src_core_id = disp_get_core_id();
    coreData->dst_core_id = mpid;
    coreData->src_arch_id = disp_get_core_id();
    coreData->dst_arch_id = mpid;
}

// Helper to initialize a memory region based on a capability
static struct mem_region initialize_mem_region(struct capability cap, enum region_type type) {
    struct mem_region region;
    region.mr_base = cap.u.ram.base;
    region.mr_type = type;
    region.mr_bytes = cap.u.ram.bytes;
    region.mr_consumed = 0;
    region.mrmod_size = 0;
    region.mrmod_data = 0;
    region.mrmod_slot = 0;
    return region;
}

// Helper to copy module regions to the new bootinfo structure
static size_t copy_module_regions(struct bootinfo *new_core_bootinfo, struct bootinfo *bootinfo, int start_index) {
    size_t j = start_index;
    for (size_t i = 0; i < bootinfo->regions_length; i++) {
        if (bootinfo->regions[i].mr_type == RegionType_Module) {
            new_core_bootinfo->regions[j] = bootinfo->regions[i];
            j++;
        }
    }
    return j; // Return the next available index
}


/**
 * @brief boots a new core with the provided mpid
 *
 * @param[in]  mpid         The ARM MPID of the core to be booted
 * @param[in]  boot_driver  Path of the boot driver binary
 * @param[in]  cpu_driver   Path of the CPU driver binary
 * @param[in]  init         Path to the init binary
 * @param[out] core         Returns the coreid of the booted core
 *
 * @return SYS_ERR_OK on success, errval on failure
 */
errval_t coreboot_boot_core(hwid_t mpid, const char *boot_driver, const char *cpu_driver,
                            const char *init, coreid_t *core)
{
    // Implement me!
    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    //   Note that it should at least OBJSIZE_KCB, and it should also be aligned
    //   to a multiple of 16k.
    // - Get and load the CPU and boot driver binary.
    // - Relocate the boot and CPU driver. The boot driver runs with a 1:1
    //   VA->PA mapping. The CPU driver is expected to be loaded at the
    //   high virtual address space, at offset ARMV8_KERNEL_OFFSET.
    // - Allocate a page for the core data struct
    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h
    // - Find the CPU driver entry point. Look for the symbol "arch_init". Put
    //   the address in the core data struct.
    // - Find the boot driver entry point. Look for the symbol "boot_entry_psci"
    // - Flush the cache.
    // - Call the invoke_monitor_spawn_core with the entry point
    //   of the boot driver and pass the (physical, of course) address of the
    //   boot struct as argument.
    errval_t err;

    global_cpu_driver = cpu_driver;
    global_init = init;


    /**
     *  Step 1: 
        Get a new KCB(kernal control block) by retyping a RAM cap to ObjType_KernelControlBlock.
        Note that it should at least OBJSIZE_KCB, and it should also be aligned
        to a multiple of 16k.
     */

    // This is for KCB that needs to retype later
    struct capref kcb_capref;

    // Represents a chunk of raw RAM
    struct capability kcb_ram_capref;
    err = allocate_and_retype_kcb(&kcb_capref, &kcb_ram_capref);
    if (err_is_fail(err)) {
        return err;
    }

    /**
     *  Step2: Load and relocate the Boot and CPU driver
        Relocate the boot and CPU driver. The boot driver runs with a 1:1
        VA->PA mapping. The CPU driver is expected to be loaded at the
        high virtual address space, at offset ARMV8_KERNEL_OFFSET.

        It is the boot driver starts the initializtion and then cpu driver take over. 
        Need to relocate so they can excute from their designated memory region
     */
    struct mem_info cpu_mi, boot_mi;
    genvaddr_t cpu_reloc_entry_point, boot_reloc_entry_point; // need this in invoke_monitor_spawn_core later

    // Load, map, and relocate CPU driver and particularlly relocate to the ARMv8_KERNEL_OFFSET
    // Here, we search the "arch_init" to find the entry point. 
    err = load_map_relocate_driver("CPU driver", cpu_driver, "arch_init", 
                                   &cpu_reloc_entry_point, &cpu_mi, ARMv8_KERNEL_OFFSET);
    if (err_is_fail(err)) {
        return err;
    }

    // Load, map, and relocate boot driver. Search same as above
    err = load_map_relocate_driver("boot driver", boot_driver, "boot_entry_psci", 
                                   &boot_reloc_entry_point, &boot_mi, 0);
    if (err_is_fail(err)) {
        return err;
    }
    

    // Step 3: allocate memory for coreData and the stack

    // Allocate and map the core data frame
    // CoreData will be used to manage the new core
    struct capref coreData_frame;
    void *coreData_buf;
    err = allocate_and_map_frame(&coreData_frame, BASE_PAGE_SIZE, &coreData_buf, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) return err;
    struct armv8_core_data *coreData = (struct armv8_core_data *)coreData_buf;

    // Identify the capability of the core data frame (coreData_cap)
    struct capability coreData_cap;
    err = cap_direct_identify(coreData_frame, &coreData_cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't identify core data frame capability\n");
        return err;
    }

    // Allocate RAM for the stack and identify its capability
    struct capref stack_ram;
    struct capability stack_cap;
    err = allocate_and_identify_ram(&stack_ram, 16 * BASE_PAGE_SIZE, &stack_cap);
    if (err_is_fail(err)) return err;


    // Step 4: Read to fill in the core data struct
    // Locate the init binary module
    struct mem_region *init_binary_region = multiboot_find_module(bi, init);
    if (init_binary_region == NULL) {
        debug_printf("Couldn't find init module\n");
        return -1;
    }

    // Define memory region for the monitor binary
    struct armv8_coredata_memreg monitor_binary = {
        .base = init_binary_region->mr_base,
        .length = init_binary_region->mrmod_size
    };

    // Allocate memory for the init process and identify its capability
    struct capref initProcess_ram;
    struct capability initProcess_cap;
    size_t init_process_size = ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE + ROUND_UP(monitor_binary.length, BASE_PAGE_SIZE);
    err = allocate_and_identify_ram(&initProcess_ram, init_process_size, &initProcess_cap);
    if (err_is_fail(err)) return err;
    struct armv8_coredata_memreg initProcess_mem = setup_memory_region(initProcess_cap);

    // Allocate and map URPC frame for inter-core communication
    struct capref urpc_frame;
    void *urpc_buf;
    err = allocate_and_map_frame(&urpc_frame, 3 * BASE_PAGE_SIZE, &urpc_buf, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) return err;
    global_urpc_frames[(uint64_t)mpid] = (genvaddr_t)urpc_buf;

    // Identify the URPC frame capability and set base and length in urpc_mem
    struct capability urpc_cap;
    err = cap_direct_identify(urpc_frame, &urpc_cap);
    if (err_is_fail(err)) return err;
    struct armv8_coredata_memreg urpc_mem = setup_memory_region(urpc_cap);

    // Populate the core data structure with relevant information
    initialize_core_data_struct(coreData, stack_cap, initProcess_mem, urpc_mem, 
                                monitor_binary, cpu_reloc_entry_point, mpid, kcb_ram_capref);

    
    // vscode doesn't like this cast, but the compiler requires it
    cpu_dcache_wbinv_range((vm_offset_t)coreData_buf, BASE_PAGE_SIZE);


    // Allocate RAM for the new core (256 MB)
    struct capref new_core_ram;
    struct capability new_core_ram_cap;  // Define the capability to hold identified RAM details
    err = allocate_and_identify_ram(&new_core_ram, NEW_CORE_MEM_SZ, &new_core_ram_cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't allocate RAM for new core\n");
        return err;
    }

    // Get capability for module strings which contain metadata
    struct capability mod_strings_cap;
    err = cap_direct_identify(cap_mmstrings, &mod_strings_cap);
    if (err_is_fail(err)) {
        debug_printf("Couldn't identify capability for module strings\n");
        return err;
    }

    // Initialize the new bootinfo struct for the other core
    struct mem_region new_mem_region = initialize_mem_region(new_core_ram_cap, RegionType_Empty);

    // Count all ELF module regions
    size_t module_counter = 0;
    for (size_t i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Module) {
            module_counter++;
        }
    }

    int bootinfo_size = sizeof(struct bootinfo) + ((module_counter + 1) * sizeof(struct mem_region));
    struct bootinfo *new_core_bootinfo = (struct bootinfo *)malloc(bootinfo_size);
    if (new_core_bootinfo == NULL) {
        debug_printf("Memory allocation for new core bootinfo failed\n");
        return -1;
    }

    // Populate the new core bootinfo structure
    new_core_bootinfo->regions[0] = new_mem_region;
    new_core_bootinfo->regions_length = module_counter + 1;
    new_core_bootinfo->mem_spawn_core = bi->mem_spawn_core;

    // Copy existing module regions to the new core bootinfo structure
    copy_module_regions(new_core_bootinfo, bi, 1);

    // Copy the bootinfo to the URPC buffer and flush cache
    memcpy(urpc_buf, new_core_bootinfo, bootinfo_size);
    memcpy(urpc_buf + bootinfo_size, &(mod_strings_cap.u.frame.base), sizeof(genpaddr_t));
    memcpy(urpc_buf + bootinfo_size + sizeof(genpaddr_t), &(mod_strings_cap.u.frame.bytes), sizeof(gensize_t));
    cpu_dcache_wbinv_range((vm_offset_t)urpc_buf, BASE_PAGE_SIZE);

    // Clean up allocated memory
    free(new_core_bootinfo);


    /**
     *  Call the invoke_monitor_spawn_core with the entry point
        of the boot driver and pass the (physical, of course) address of the
        boot struct as argument.
     */

    // Fix the CPU type to CPU_ARM8
    err = invoke_monitor_spawn_core(coreData->dst_arch_id, CPU_ARM8, boot_reloc_entry_point, coreData_cap.u.frame.base, 0);

    // set the return core parameter
    if (core != NULL) {
        *core = (coreid_t)mpid;
    }

    return SYS_ERR_OK;
}

/**
 * @brief shutdown the execution of the given core and free its resources
 *
 * @param[in] core  Coreid of the core to be shut down
 *
 * @return SYS_ERR_OK on success, errval on failure
 *
 * Note: calling this function with the coreid of the BSP core (0) will cause an error.
 */
errval_t coreboot_shutdown_core(coreid_t core)
{
    (void)core;
    // Hints:
    //  - think of what happens when you call this function with the coreid of another core,
    //    or with the coreid of the core you are running on.
    //  - use the BSP core as the manager.
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief shuts down the core and reboots it using the provided arguments
 *
 * @param[in] core         Coreid of the core to be rebooted
 * @param[in] boot_driver  Path of the boot driver binary
 * @param[in] cpu_driver   Path of the CPU driver binary
 * @param[in] init         Path to the init binary
 *
 * @return SYS_ERR_OK on success, errval on failure
 *
 * Note: calling this function with the coreid of the BSP core (0) will cause an error.
 */
errval_t coreboot_reboot_core(coreid_t core, const char *boot_driver, const char *cpu_driver,
                              const char *init)
{
(void)core;
(void)boot_driver;
(void)cpu_driver;
(void)init;
    // Hints:
    //  - think of what happens when you call this function with the coreid of another core,
    //    or with the coreid of the core you are running on.
    //  - use the BSP core as the manager.
    //  - after you've shutdown the core, you can reuse `coreboot_boot_core` to boot it again.

    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief suspends (halts) the execution of the given core
 *
 * @param[in] core  Coreid of the core to be suspended
 *
 * @return SYS_ERR_OK on success, errval on failure
 *
 * Note: calling this function with the coreid of the BSP core (0) will cause an error.
 */
errval_t coreboot_suspend_core(coreid_t core)
{
    (void)core;
    // Hints:
    //  - think of what happens when you call this function with the coreid of another core,
    //    or with the coreid of the core you are running on.
    //  - use the BSP core as the manager.

    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief resumes the execution of the given core
 *
 * @param[in] core  Coreid of the core to be resumed
 *
 * @return SYS_ERR_OK on success, errval on failure
 */
errval_t coreboot_resume_core(coreid_t core)
{
    (void)core;
    // Hints:
    //  - check if the coreid is valid and the core is in fact suspended
    //  - wake up the core to resume its execution

    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}



/**
 * @brief obtains the number of cores present in the system.
 *
 * @param[out] num_cores  returns the number of cores in the system
 *
 * @return SYS_ERR_OK on success, errval on failure
 *
 * Note: This function should return the number of cores that the system supports
 */
errval_t coreboot_get_num_cores(coreid_t *num_cores)
{
    // TODO: change me with multicore support!
    *num_cores = 1;
    return SYS_ERR_OK;
}


/**
 * @brief obtains the status of a core in the system.
 *
 * @param[in]  core    the ID of the core to obtain the status from
 * @param[out] status  status struct filled in
 *
 * @return SYS_ERR_OK on success, errval on failure
 */
errval_t coreboot_get_core_status(coreid_t core, struct corestatus *status)
{
    (void)core;
    (void)status;
    // TODO: obtain the status of the core.
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}