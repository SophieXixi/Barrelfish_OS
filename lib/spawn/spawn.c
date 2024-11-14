/*
 * Copyright (c) 2016, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>

#include <elf/elf.h>
#include <spawn/spawn.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>
#include <spawn/elfimg.h>
#include <aos/cspace.h>
#include <aos/paging.h>
#include <aos/morecore.h>
#include <aos/morecore.h>



#define HEAP_ALLOC_SIZE (256 << 10)

#define HEAP_ALLOC_SIZE (256 << 10)




/**
 * @brief Sets the initial values of some registers in the dispatcher
 *
 * @param[in] handle    dispatcher handle to the child's dispatcher
 * @param[in] entry     entry point of the new process
 * @param[in] got_base  the base address of the global offset table
 *
 */
__attribute__((__used__)) static void armv8_set_registers(dispatcher_handle_t handle,
                                                          lvaddr_t entry, lvaddr_t got_base)
{
    assert(got_base != 0);
    assert(entry != 0);

    // set the got_base in the shared struct
    struct dispatcher_shared_aarch64 *disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base                         = got_base;

    // set the got_base in the registers for the enabled case
    arch_registers_state_t *enabled_area         = dispatcher_get_enabled_save_area(handle);
    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;

    // set the got_base in the registers for the disabled case
    arch_registers_state_t *disabled_area         = dispatcher_get_disabled_save_area(handle);
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->named.pc                       = entry;
}




/**
 * @brief constructs a new process by loading the image from the bootinfo struct
 *
 * @param[in] si    spawninfo structure to fill in
 * @param[in] bi    pointer to the bootinfo struct
 * @param[in] name  name of the binary in the bootinfo struct
 * @param[in] pid   the process id (PID) for the new process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note, this function prepares a new process for running, but it does not make it
 * runnable. See spawn_start().
 */
errval_t spawn_load_with_bootinfo(struct spawninfo *si, struct bootinfo *bi, const char *name,
                                  domainid_t pid)
{
    // make compiler happy about unused parameters
    (void)si;
    (void)bi;
    (void)name;
    (void)pid;

    // TODO: Implement me

    // - Get the module from the multiboot image
    char module_name[128];
    sscanf(name, "%127s", module_name); 
    struct mem_region *module = multiboot_find_module(bi, module_name);
    printf("Module found for %s at base address: 0x%lx\n", module_name, module->mr_base);
    printf("STRING USED%s\n", name);


    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = module->mrmod_slot,
    };

    // - Map multiboot module in your address space
    struct frame_identity child_frame_id;
    errval_t err = frame_identify(child_frame, &child_frame_id);
    lvaddr_t mapped_elf;
    err = paging_map_frame(get_current_paging_state(), (void**)&mapped_elf,
                           module->mrmod_size, child_frame);

    printf("ELF header: %0x %c %c %c", ((char*)mapped_elf)[0], ((char*)mapped_elf)[1], ((char*)mapped_elf)[2], ((char*)mapped_elf)[3]);

    si->child_frame_id = child_frame_id;
    si->mapped_elf = mapped_elf;
    si->module = module;
    // - create the elfimg struct from the module
    struct elfimg img;
    elfimg_init_from_module(&img, module);
    printf("Created elf image\n");



    // - Fill in argc/argv from the multiboot command line
    //const char *cmdline = multiboot_module_opts(module);
    int argc;  // `argc` is declared without being initialized
    char *buf = NULL;  // `buf` is initialized to NULL
    char **argv = make_argv(name, &argc, &buf);
    if (!argv) {
        debug_printf("Error: Failed to parse arguments from command line\n");
        return SPAWN_ERR_CREATE_ARGSPG;
    }
    printf("Created arguments argc = %d\n", argc);

    // Print out each argument to verify
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }

    // Allocate and copy the binary name
    si->binary_name = malloc(strlen((char*)argv[0]) + 1);
    if (si->binary_name == NULL) {
        debug_printf("malloc failed\n");
        abort();
    }
    strcpy(si->binary_name, (char*) argv[0]);
    printf("BINARY NAME: %s\n", si->binary_name);


    // Proceed with finding the .got section header
    struct Elf64_Shdr *got_section_header = elf64_find_section_header_name((genvaddr_t)si->mapped_elf, si->module->mrmod_size, ".got");
    printf("found section header initial%d\n", *got_section_header);

    // Call spawn_load_with_args
    err = spawn_load_with_args(si, &img, argc, (const char **)argv, pid);

    (void)err;
    printf("SPAWN ENTRY ADDRESS: %p\n", (void*)si->entry_addr);


    return SYS_ERR_OK;
}

/**
 * @brief constructs a new process from the provided image pointer
 *
 * @param[in] si    spawninfo structure to fill in
 * @param[in] img   pointer to the elf image in memory
 * @param[in] argc  number of arguments in argv
 * @param[in] argv  command line arguments
 * @param[in] capc  number of capabilities in the caps array
 * @param[in] caps  array of capabilities to pass to the child
 * @param[in] pid   the process id (PID) for the new process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note, this function prepares a new process for running, but it does not make it
 * runnable. See spawn_start().
 */
// Forward declarations
static errval_t initialize_spawn_info(struct spawninfo *si, const char *binary_name, domainid_t pid);
static errval_t setup_child_cspace(struct spawninfo *si);
// static errval_t populate_task_cnode(struct cnoderef task_cnode, struct spawninfo *si);
static errval_t initialize_child_vspace(struct spawninfo *si);

static errval_t setup_dispatcher(struct spawninfo *si, domainid_t pid);
static errval_t setup_args(struct spawninfo *si, int argc, const char *argv[]);

/**
 * @brief constructs a new process from the provided image pointer
 *
 * @param[in] si    spawninfo structure to fill in
 * @param[in] img   pointer to the elf image in memory
 * @param[in] argc  number of arguments in argv
 * @param[in] argv  command line arguments
 * @param[in] capc  number of capabilities in the caps array
 * @param[in] caps  array of capabilities to pass to the child
 * @param[in] pid   the process id (PID) for the new process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note, this function prepares a new process for running, but it does not make it
 * runnable. See spawn_start().
 */
errval_t spawn_load_with_caps(struct spawninfo *si, struct elfimg *img, int argc,
                              const char *argv[], int capc, struct capref caps[], domainid_t pid)
{
    errval_t err;
    (void)capc;
    (void)caps;
    (void)argc;
    (void)argv;

    // Step 1: Initialize spawn_info
    err = initialize_spawn_info(si, argv[0], pid);
    if (err_is_fail(err)) {
        debug_printf("Failed to initialize spawn info: %s\n", err_getstring(err));
        return err;
    }

    // Step 2: Setup child's CSpace (create CNodes)
    err = setup_child_cspace(si);
    if (err_is_fail(err)) {
        debug_printf("Failed to setup child CSpace: %s\n", err_getstring(err));
        return err;
    }
    printf("DONE SETTING UP CSPACE\n");

    // Copy the caps passed in to L2CNode[ROOTCN_SLOT_ALLOC_0]
    for (int i = 0; i < capc; i++) {
        struct capref temp;
        temp.cnode = si->l2_cnodes[ROOTCN_SLOT_SLOT_ALLOC0];
        temp.slot = (cslot_t) i;
        err = cap_copy(temp, caps[i]);
        if (err_is_fail(err)) {
            USER_PANIC("copying caps passed into child fail: %s\n", err_getstring(err));
        }
    }

    // Step 3: Initialize child's VSpace and load ELF
    err = initialize_child_vspace(si);
    if (err_is_fail(err)) {
        debug_printf("Failed to initialize child VSpace: %s\n", err_getstring(err));
        return err;
    }
    printf("DONE SETTING UP VSPACE\n");
    (void)img;
    printf("SPAWN ENTRY ADDRESS: %p\n", (void*)si->entry_addr);

    // Step 4: Load the ELF image into the child's VSpace
    err = elf_load(EM_AARCH64, allocate_child_frame, si->paging_state, si->mapped_elf,
                   si->module->mrmod_size, &si->entry_addr);
                       printf("SPAWN ENTRY ADDRESS: %p\n", (void*)si->entry_addr);

    if (err_is_fail(err)) {
        debug_printf("Failed to load ELF: %s\n", err_getstring(err));
        return err;
    }
    printf("LOADED THE ELF");

    // step 5: set up the dispatcher
    setup_dispatcher(si, pid);
    printf("finished dispatcher and go in set args\n");

    // step 6: setup the environment
    setup_args(si, argc, argv);

    
    return SYS_ERR_OK;
}

// --- Step-by-Step Helper Functions ---

// Step 1: Initialize the spawn_info struct
static errval_t initialize_spawn_info(struct spawninfo *si, const char *binary_name, domainid_t pid)
{
    si->pid = pid;
    //si->binary_name = (char *)binary_name;
    si->cmdline = (char *)binary_name;
    si->state = SPAWN_STATE_SPAWNING;
    si->exitcode = 0;
    si->children = NULL;
    si->num_children = 0;
    printf("Initialized spawninfo for PID %u with binary %s\n", pid, si->binary_name);
    return SYS_ERR_OK;
}

// Step 2: Setup child's CSpace with required CNodes and populate Task CNode
static errval_t setup_child_cspace(struct spawninfo *si)
{
    struct capref l1_cap;
    // Step 1: CREATING L1 AND L2 CNODES
    errval_t err = cnode_create_l1(&l1_cap, &si->l1_cnode);
    if (err_is_fail(err)) {
        debug_printf("Error creating L1 CNode %s\n", err_getstring(err));
        debug_printf("Error creating L1 CNode %s\n", err_getstring(err));
        return err;
    }
    si->l1_cap = l1_cap;
    printf("Created L1 CNode\n");

    for (size_t i = 0; i < ROOTCN_SLOTS_USER; ++i) {
        err = cnode_create_foreign_l2(l1_cap, i, &si->l2_cnodes[i]);
        if (err_is_fail(err)) {
            debug_printf("Error creating foreign L2 CNode: %s\n", err_getstring(err));
            return err;
        }
    }

    printf("Make capabilities for the L2 CNODES\n");
    si->slot_alloc0_cap = (struct capref){
        .cnode = si->l1_cnode,
        .slot = ROOTCN_SLOT_SLOT_ALLOC0    
     };

    si->slot_alloc1_cap = (struct capref){
        .cnode = si->l1_cnode,
        .slot = ROOTCN_SLOT_SLOT_ALLOC1    
    };

    si->slot_alloc2_cap = (struct capref){
        .cnode = si->l1_cnode,
        .slot = ROOTCN_SLOT_SLOT_ALLOC2
    };

    si->pagecn_cap = (struct capref){
        .cnode = si->l1_cnode,
        .slot = ROOTCN_SLOT_PAGECN
    };

    si->taskcn_cap = (struct capref){ 
        .cnode = si->l1_cnode,
        .slot = ROOTCN_SLOT_TASKCN
    };

    si->taskcn_root = (struct capref){ 
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_ROOTCN
    };
    err = cap_copy(si->taskcn_root, l1_cap);

    struct capref earlymem_cap;

    err = ram_alloc(&earlymem_cap, BASE_PAGE_SIZE * 1024);
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate early memory: %s\n", err_getstring(err));
        return err;
    }
    // Set up the destination cap in the child’s CSpace
    si->earlymem_cap = (struct capref){
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_EARLYMEM
    };

    // Copy the EARLYMEM cap to the child’s CSpace
    err = cap_copy(si->earlymem_cap, earlymem_cap);
    if (err_is_fail(err)) { 
        debug_printf("Failed to copy EARLYMEM to child: %s\n", err_getstring(err));
        return err;
    }


    struct capref croot = get_croot_capref(si->earlymem_cap);
    struct capability cap;
    printf("si->earlymem_cap details:\n");
    printf("  si->earlymem_cap slot: %d\n", si->earlymem_cap.slot);
    printf("  si->earlymem_cap cnode: %d\n", si->earlymem_cap.cnode);
    printf("  si->earlymem_cap cnode cnode: %d\n", si->earlymem_cap.cnode.cnode);
    printf("  si->earlymem_cap cnode croot: %d\n", si->earlymem_cap.cnode.croot);
    printf("  si->earlymem_cap cnode level: %d\n", si->earlymem_cap.cnode.level);

    printf("  cnode_task cnode: %d\n", cnode_task.cnode);
    printf("  cnode_task croot: %d\n", cnode_task.croot);
    printf("  cnode_task croot: %d\n", cnode_task.level);

    cnode_task = si->l2_cnodes[ROOTCN_SLOT_TASKCN];
    printf("  cnode_task cnode: %d\n", cnode_task.cnode);
    printf("  cnode_task croot: %d\n", cnode_task.croot);
    printf("  cnode_task croot: %d\n", cnode_task.level);


    err = cap_direct_identify(si->earlymem_cap, &cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }


    printf("SPAWN Invoking capability identify:\n");
    printf("  Root cap: croot.cnode = %u, croot.slot = %u\n", croot.cnode, croot.slot);
    printf("  Capability address: 0x%lx\n", get_cap_addr(si->earlymem_cap));
    printf("  Capability level: %u\n", get_cap_level(si->earlymem_cap));


    // Confirm the EARLYMEM capability was copied successfully
    debug_printf("EARLYMEM cap copied successfully to child CSpace: CNode = %d, Slot = %d\n",
                si->earlymem_cap.cnode.croot, si->earlymem_cap.slot);





if (err_is_fail(err)) {
    debug_printf("Failed to copy EARLYMEM to child: %s\n", err_getstring(err));
    return err;
} else {
    debug_printf("EARLYMEM capability successfully copied to TASKCN_SLOT_EARLYMEM.\n");
}

        printf("CSPACE setup for child completed.\n");
    return SYS_ERR_OK;

}

// Step 3: Initialize the child's VSpace
static errval_t initialize_child_vspace(struct spawninfo *si)
{   
    (void)si;
    size_t bufsize = SINGLE_SLOT_ALLOC_BUFLEN(L2_CNODE_SLOTS);
    void *buf = malloc(bufsize);
    assert(buf != NULL);

    printf("  &si->single_slot_alloc: %p\n", (void*)&si->single_slot_alloc);


    printf("  si->l2_cnodes[ROOTCN_SLOT_PAGECN]: cnode = %u, slot = %u\n", 
        si->l2_cnodes[ROOTCN_SLOT_PAGECN].cnode, si->l2_cnodes[ROOTCN_SLOT_PAGECN].croot);


    errval_t err = single_slot_alloc_init_raw(&si->single_slot_alloc, si->pagecn_cap,
                                              si->l2_cnodes[ROOTCN_SLOT_PAGECN], L2_CNODE_SLOTS, buf, bufsize);


    struct capref l0_pagetable_cap;
    err = si->single_slot_alloc.a.alloc(&si->single_slot_alloc.a, &l0_pagetable_cap);  // Allocate a slot in the parent CSpace
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate slot for L0 page table: %s\n", err_getstring(err));
        return err;
    }

    err = vnode_create(l0_pagetable_cap, ObjType_VNode_AARCH64_l0);
    printf("VNODE CREATE AND COPY");

    si->paging_state = malloc(sizeof(struct paging_state));
        if (si->paging_state == NULL) {
            debug_printf("malloc failed\n");
            return LIB_ERR_MALLOC_FAIL;
        }
    printf("MALLOC succeeded\n");

    err = paging_init_state_foreign(si->paging_state, VADDR_OFFSET, l0_pagetable_cap, get_default_slot_allocator());
    if (err_is_fail(err)) {
        debug_printf("Failed to initialize child paging state: %s\n", err_getstring(err));
        return err;
    }


    si->childl0_pagetable.cnode = si->l2_cnodes[ROOTCN_SLOT_PAGECN];  // Set child’s L0 location
    si->childl0_pagetable.slot = PAGECN_SLOT_VROOT;  // Assign first slot for L0 tables
    cap_copy(si->childl0_pagetable, l0_pagetable_cap);

    printf("Child paging state initialized successfully\n");
    return SYS_ERR_OK;
}

// allocate function for elf
errval_t allocate_child_frame(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret)
{
    errval_t err;
    (void)state;
    (void)base;
    (void)flags;
    void *retval;


    // Step 1: Calculate offset and adjust base and size for page alignment
    genvaddr_t init_base = base;
    base = ROUND_DOWN(base, BASE_PAGE_SIZE);
    size = ROUND_UP(base + size, BASE_PAGE_SIZE) - base;

    // Step 2: Allocate a frame for the required size
    struct capref frame;
    size_t allocated_size;
    err = frame_alloc(&frame, size, &allocated_size);
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate frame: %s\n", err_getstring(err));
        return err;
    }
    // // Step 3: Map the frame at the specified fixed address in the child’s address space
    err = paging_map_fixed_attr(state, base, frame, size, flags);
    if (err_is_fail(err)) {
        debug_printf("Failed to map frame at fixed address in child's address space: %s\n", err_getstring(err));
        return err;
    }
    printf("Mapped frame in child's virtual address space at fixed address: 0x%lx\n", base);

    // Step 4: Use morecore_alloc to allocate memory in the parent’s address space for ELF loading
    err = paging_map_frame(get_current_paging_state(), &retval, size, frame);
    if (err_is_fail(err)) {
        debug_printf("Failed to map frame at fixed address in parent address space: %s\n", err_getstring(err));
        return err;
    }
    printf("Mapped frame in parent's address space at address: %p\n", *ret);

    // Step 5: Adjust `ret` by `offset` so that it points to the correct location
    // Debug information
    *ret = retval + (init_base - base);
    printf("Mapped address in parent (ret): %p\n", *ret);
    printf("size of what we just mapped: %p\n", size);
    return SYS_ERR_OK;
}


static errval_t setup_dispatcher(struct spawninfo *si, domainid_t pid)
{
    (void)pid;
    printf("Invoking setup dispatcher function\n");

    // Allocate slot for dispatcher
    struct capref dispatcher_parent;
    errval_t err = slot_alloc(&dispatcher_parent);
    if (err_is_fail(err)) {
        printf("Failed to allocate slot for dispatcher\n");
        return err;
    }
    printf("Slot allocated for dispatcher\n");

    // Create dispatcher
    err = dispatcher_create(dispatcher_parent);
    if (err_is_fail(err)) {
        printf("Failed to create dispatcher\n");
        return SPAWN_ERR_DISPATCHER_SETUP;
    }

    struct capref selfep;
    err = cap_retype(selfep, dispatcher_parent, 0, ObjType_EndPointLMP, 0);

    si->selfep_cap.cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN];
    si->selfep_cap.slot = TASKCN_SLOT_SELFEP;
    cap_copy(si->selfep_cap, selfep);
    printf("Remote endpoint capability set SPAWN:\n");
    printf("  cnode.croot = %u, cnode.cnode = %u, cnode.level = %u\n", 
           si->selfep_cap.cnode.croot, si->selfep_cap.cnode.cnode, si->selfep_cap.cnode.level);
    printf("  slot = %u\n", si->selfep_cap.slot);


    // Allocate dispatcher frame for parent
    struct capref dispframe_parent;
    err = frame_alloc(&dispframe_parent, DISPATCHER_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        printf("Failed to allocate dispatcher frame for parent process\n");
        return SPAWN_ERR_DISPATCHER_SETUP;
    }

    // Map dispatcher frame to parent and child processes
    void *parent_buffer, *child_buffer;
    err = paging_map_frame_attr(get_current_paging_state(), &parent_buffer, DISPATCHER_FRAME_SIZE, dispframe_parent, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        printf("Failed to map dispatcher to parent\n");
        return SPAWN_ERR_DISPATCHER_SETUP;
    }
    err = paging_map_frame_attr(si->paging_state, &child_buffer, DISPATCHER_FRAME_SIZE, dispframe_parent, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        printf("Failed to map dispatcher to child\n");
        return SPAWN_ERR_DISPATCHER_SETUP;
    }
    printf("Dispatcher frame mapped for both parent and child\n");

    // Copy dispatcher cap and frame to child
    struct capref child_dispcap = { .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN], .slot = TASKCN_SLOT_DISPATCHER };
    err = cap_copy(child_dispcap, dispatcher_parent);
    if (err_is_fail(err)) {
        printf("Failed to copy dispatcher cap to child\n");
        return err;
    }

    struct capref child_dispframe = { .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN], .slot = TASKCN_SLOT_DISPFRAME };
    err = cap_copy(child_dispframe, dispframe_parent);
    if (err_is_fail(err)) {
        printf("Failed to copy dispatcher frame to child\n");
        return err;
    }

    si->dispatcher_child = child_dispcap;
    si->dispframe_child = child_dispframe;
    si->dispatcher_parent = dispatcher_parent;
    si->dispframe_parent = dispframe_parent;

    // Initialize dispatcher structures
    struct dispatcher_shared_generic *disp_share = get_dispatcher_shared_generic((dispatcher_handle_t)parent_buffer);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic((dispatcher_handle_t)parent_buffer);
    
    // arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area((dispatcher_handle_t)parent_buffer);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area((dispatcher_handle_t)parent_buffer);

    // Set core and domain IDs
    disp_gen->core_id = disp_get_core_id();
    disp_gen->domain_id = pid;
    printf("PID: %d\n", disp_gen->domain_id);
    printf("PID: %d\n", pid);


    // Set up dispatcher fields
    disp_share->udisp = (lvaddr_t)child_buffer; // Virtual address in child’s VSpace
    disp_share->disabled = 1;                   // Start in disabled mode
    strncpy(disp_share->name, si->binary_name, DISP_NAME_LEN);

    // Find .got section and initialize registers
    struct Elf64_Shdr *got_section_header = elf64_find_section_header_name((genvaddr_t)si->mapped_elf, si->module->mrmod_size, ".got");
    printf("found section header%d\n", *got_section_header);

    disabled_area->named.pc = si->entry_addr;
    printf("disabled area: %p\n", disabled_area->named.pc);
    printf("si entry address: %p\n", si->entry_addr);




    armv8_set_registers((dispatcher_handle_t)parent_buffer, si->entry_addr, got_section_header->sh_addr);

    // Error handling frames (unused in this case)
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;
    si->handle = (dispatcher_handle_t)parent_buffer;


    printf("Setup dispatcher completed successfully\n");
    return SYS_ERR_OK;
}

// setup the args and the environment
// setup the args and the environment
static errval_t setup_args(struct spawninfo *si, int argc, const char *argv[])
{
    printf("invoking setup the args function\n");
    struct capref args_cap = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_ARGSPAGE
    };
    void *parent_args;
    void *child_args;
    errval_t err;
    err = frame_alloc(&args_cap, ARGS_SIZE, NULL);
    if (err_is_fail(err)) {
        return LIB_ERR_FRAME_ALLOC;
    }
    printf("finished frame alloc for args\n");
    err = paging_map_frame_attr(get_current_paging_state(), &parent_args, ARGS_SIZE, args_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return SPAWN_ERR_MAP_ARGSPG_TO_SELF;
    }
    printf("finished paging map for both parent \n");
    err = paging_map_frame_attr(si->paging_state, &child_args, ARGS_SIZE, args_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return SPAWN_ERR_MAP_ARGSPG_TO_NEW;
    }
    printf("finished paging map for child \n");
    // fill in args in parent
    struct spawn_domain_params *sdp = (struct spawn_domain_params *)parent_args;
    memset(parent_args, 0, ARGS_SIZE);
    if (argc > MAX_CMDLINE_ARGS) {
        return ERR_INVALID_ARGS;
    }
    printf("finished set parent memory to 0\n");
    int offset = 0;
    for (int i = 0; i < argc; i++) {
        strncpy(parent_args + sizeof(struct spawn_domain_params) + offset, argv[i], strlen(argv[i]) + 1);
        sdp->argv[i] = child_args + sizeof(struct spawn_domain_params) + offset;
        offset += strlen(argv[i]) + 1;
    }
    printf("finished filled in the argv\n");
    sdp->argc = argc;
    // terminate
    sdp->argv[argc] = NULL;
    printf("finished setup args, begin to set registers\n");
    // the first argument in the enabled area in the child process is the spawn domain params pointer.
    registers_set_param(dispatcher_get_enabled_save_area(si->handle), (lvaddr_t)child_args);
    printf("finished setup the registers\n");
    return SYS_ERR_OK;
}

/**
 * @brief starts the execution of the new process by making it runnable
 *
 * @param[in] si   spawninfo structure of the constructed process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_start(struct spawninfo *si)
{
    // make compiler happy about unused parameters
    (void)si;

    // TODO:
    //  - check whether the process is in the right state (ready to be started)
    //  - invoke the dispatcher to make the process runnable
    //  - set the state to running
    if (si->state != SPAWN_STATE_READY) {
        return SPAWN_ERR_RUN;
    }
    // !!!
    errval_t err = invoke_dispatcher(si->dispatcher_parent, cap_dispatcher, si->l1_cap, si->childl0_pagetable, si->dispframe_child, true);
    if (err_is_fail(err)) {
        printf("fail to invoke the dispatcher\n");
        return err;
    }
    printf("INVOKED THE DISPATCHER\n");
    si->state = SPAWN_STATE_RUNNING;
    // USER_PANIC("Not implemented");
    return SYS_ERR_OK;
}

/**
 * @brief resumes the execution of a previously stopped process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_resume(struct spawninfo *si)
{
    // make compiler happy about unused parameters

    // TODO:
    //  - check whether the process is in the right state
    //  - resume the execution of the process
    //  - set the state to running
    if (si->state != SPAWN_STATE_SUSPENDED) {
        return SPAWN_ERR_WRONG_STATE;  // The process is not in a state that can be suspended
    }

    // Stop the execution of the process using its dispatcher capability
    errval_t err = invoke_dispatcher_resume(si->dispatcher_child);
    if(err_is_fail(err)) {
        printf("Error resuming dispatcher");
        return err;
    }
    // Update the state of the process to reflect that it has been killed

    return SYS_ERR_OK;
}

/**
 * @brief stops/suspends the execution of a running process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_suspend(struct spawninfo *si)
{
    // Check if the process is in a state that allows it to be stopped
    if (si->state != SPAWN_STATE_RUNNING) {
        return SPAWN_ERR_WRONG_STATE;  // The process is not in a state that can be suspended
    }

    // Stop the execution of the process using its dispatcher capability
    errval_t err = invoke_dispatcher_stop(si->dispatcher_child);
    if(err_is_fail(err)) {
        printf("Error stopping dispatcher");
        return err;
    }
    // Update the state of the process to reflect that it has been killed

    return SYS_ERR_OK;
}

/**
 * @brief stops the execution of a running process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_kill(struct spawninfo *si)
{

    // Check if the process is in a state that allows it to be stopped
    if (si->state != SPAWN_STATE_RUNNING && si->state != SPAWN_STATE_SUSPENDED) {
        return SPAWN_ERR_WRONG_STATE;  // The process is not in a state that can be killed
    }

    // Stop the execution of the process using its dispatcher capability
    errval_t err = invoke_dispatcher_stop(si->dispatcher_child);
    if(err_is_fail(err)) {
        printf("Error stopping dispatcher");
        return err;
    }
    // Update the state of the process to reflect that it has been killed
    

    return SYS_ERR_OK;
}

/**
 * @brief marks the process as having exited
 *
 * @param[in] si        spawninfo structure of the process
 * @param[in] exitcode  exit code of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * The process manager should call this function when it receives the exit
 * notification from the child process. The function makes sure that the
 * process is no longer running and can be cleaned up later on.
 */
errval_t spawn_exit(struct spawninfo *si, int exitcode)
{
    // make compiler happy about unused parameters
    (void)si;
    (void)exitcode;

    // TODO:
    //  - check whether the process is in the right state
    //  - stop the execution of the process, update the exit code
    //  - set the state to terminated
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief cleans up the resources of a process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: The process has to be stopped before calling this function.
 */
errval_t spawn_cleanup(struct spawninfo *si)
{
    // make compiler happy about unused parameters
    (void)si;

    // Resources need to be cleaned up at some point. How would you go about this?
    // This is certainly not an easy task. You need to track down all the resources
    // that the process was using and collect them. Recall, in Barrelfish all the
    // resources are represented by capabilities -- so you could, in theory, simply
    // walk the CSpace of the process. Then, some of the resources you may have kept
    // in the process manager's CSpace and created mappings in the VSpace.
    //
    // TODO(not required):
    //  - cleanup the resources of the process
    //  - clean up the resources in the process manager
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief initializes the IPC channel for the process
 *
 * @param[in] si       spawninfo structure of the process
 * @param[in] ws       waitset to be used
 * @param[in] handler  message handler for the IPC channel
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this functionality is required for the IPC milestone.
 *
 * Hint: the IPC subsystem should be initialized before the process is being run for
 * the first time.
 */
errval_t spawn_setup_ipc(struct spawninfo *si, struct waitset *ws, aos_recv_handler_fn handler)
{
    (void)handler;
    (void)ws;

    errval_t err;

    // check the execution state of the process (it shouldn't have run yet)
    if (si->state != SPAWN_STATE_READY) {
        return SPAWN_ERR_LOAD;
    }

    // create the struct chan (TODO: if we ever need access to this struct on init side, good luck!)
    struct aos_rpc *rpc = malloc(sizeof(struct aos_rpc));    
    if (rpc == NULL) {
        return SPAWN_ERR_LOAD;
    }
    err = aos_rpc_init(rpc);
  
    err = lmp_chan_accept(rpc->channel, DEFAULT_LMP_BUF_WORDS, cap_initep);

    return SYS_ERR_OK;
}


/**
 * @brief sets the receive handler function for the message channel
 *
 * @param[in] si       spawninfo structure of the process
 * @param[in] handler  handler function to be set
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_set_recv_handler(struct spawninfo *si, aos_recv_handler_fn handler)
{
    // make compiler happy about unused parameters
    (void)si;
    (void)handler;

    // TODO:
    //  - set the custom receive handler for the message channel
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
}