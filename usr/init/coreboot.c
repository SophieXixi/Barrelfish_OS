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


extern struct platform_info platform_info;
extern struct bootinfo     *bi;

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
    // make compiler happy about unused parameters
    (void)init;
    (void)boot_driver;
    (void)cpu_driver;
    // make compiler happy about unused parameters
    (void)core;
    (void)mpid;

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

    debug_printf("WARNING: Spawning cores not yet implemented on this platform.\n");
    return LIB_ERR_NOT_IMPLEMENTED;
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