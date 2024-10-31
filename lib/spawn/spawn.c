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
    struct mem_region *module = multiboot_find_module(bi, name);
    printf("Module found for %s at base address: 0x%lx\n", name, module->mr_base);

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


    // - create the elfimg struct from the module
    struct elfimg img;
    elfimg_init_from_module(&img, module);
    printf("Created elf image\n");

    // - Fill in argc/argv from the multiboot command line
    const char *cmdline = multiboot_module_opts(module);
    int argc;  // `argc` is declared without being initialized
    char *buf = NULL;  // `buf` is initialized to NULL
    char **argv = make_argv(cmdline, &argc, &buf);  // `make_argv` will set `argc` and `buf`
    if (!argv) {
        debug_printf("Error: Failed to parse arguments from command line\n");
        return SPAWN_ERR_CREATE_ARGSPG;
    }
    printf("Created arguments argc and argv\n");


    // - Call spawn_load_with_args
    err = spawn_load_with_args(si, &img, argc, (const char **)argv, pid);

    (void)err;
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

static errval_t setup_dispatcher(struct spawninfo *si);




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
    printf("DONE SETTING UP CSPACE");

    // Step 3: Initialize child's VSpace and load ELF
    err = initialize_child_vspace(si);
    if (err_is_fail(err)) {
        debug_printf("Failed to initialize child VSpace: %s\n", err_getstring(err));
        return err;
    }
    printf("DONE SETTING UP VSPACE");
    (void)img;

    // Step 4: Load the ELF image into the child's VSpace
    err = elf_load(EM_AARCH64, allocate_child_frame, (void *) si->paging_state, si->mapped_elf,
                   si->child_frame_id.bytes, &si->entry_addr);
    printf("LOADED THE ELF 1");
    if (err_is_fail(err)) {
        debug_printf("Failed to load ELF: %s\n", err_getstring(err));
        return err;
    }
    printf("LOADED THE ELF");

    // Other steps for dispatcher, environment setup, and register setup will follow here
    // e.g., setup_dispatcher(), setup_environment(), configure_registers()
    err = setup_dispatcher(si);
    if (err_is_fail(err)) {
        debug_printf("Failed to setup DISPATCHER: %s\n", err_getstring(err));
        return err;
    }
    printf("SETUP DISPATCHER DONE");


    

    USER_PANIC("Not implemented");  // Placeholder for further implementation
    return LIB_ERR_NOT_IMPLEMENTED;
}

// --- Step-by-Step Helper Functions ---

// Step 1: Initialize the spawn_info struct
static errval_t initialize_spawn_info(struct spawninfo *si, const char *binary_name, domainid_t pid)
{
    si->pid = pid;
    si->binary_name = (char *)binary_name;
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

    // CREATING INITIAL L1 CNODE for SPAWN INFO
    errval_t err = cnode_create_l1(&si->l1_cap, &si->l1_cnode);
    if (err_is_fail(err)) {
        debug_printf("Error creating l1 cnode %s", err_getstring(err));
        return err;
    }
    printf("Created l1_cnode");

    // CREATING L2 CNODES FOR SPAWN INFO
    for (size_t i = 0; i < ROOTCN_SLOTS_USER; ++i) {
        err = cnode_create_foreign_l2(si->l1_cap, i, &si->l2_cnodes[i]);
        if (err_is_fail(err)) {
            debug_printf("Error during paging_map_frame: %s", err_getstring(err));
            return err;
        }
    }
    printf("Created l2_cnodes");

    // TASK CN CNODE PUTTING INTO L1 CAP 
    struct capref taskcn_cnode = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_ROOTCN };

    err = cap_copy(taskcn_cnode, si->l1_cap);
    if (err_is_fail(err)) {
        debug_printf("Error during copy of L1Cnode cap to taskcn: %s", err_getstring(err));
        return err;
    }

    // allocate BASE_PAGE_CN slots 
    struct capref cap = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_BASE_PAGE_CN]
    };

    for (cap.slot = 0; cap.slot < L2_CNODE_SLOTS; ++cap.slot) {
        struct capref ram_for_base_page;
        err = ram_alloc(&ram_for_base_page, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            debug_printf("Error during BASE_PAGE_CN ram_alloc");
            return err;
        }
        err = cap_copy(cap, ram_for_base_page);
        if (err_is_fail(err)) {
            debug_printf("Error during cap copy in BASE_PAGE_CN slot filling: %s");
            return err;
            cap_destroy(ram_for_base_page);
        }
    }

    printf("CSPACE DONE INIT");
    return SYS_ERR_OK;
}


// Step 3: Initialize the child's VSpace
static errval_t initialize_child_vspace(struct spawninfo *si)
{
    errval_t err;
    //struct paging_state *parent_paging_state = get_current_paging_state();
    struct paging_state *child_paging_state = malloc(sizeof(struct paging_state));
    if (!child_paging_state) {
        debug_printf("Failed to allocate memory for child paging state\n");
        return LIB_ERR_MALLOC_FAIL;
    }
    
    
    slot_alloc(&si->l0pagetable); 
    err = vnode_create(si->l0pagetable, ObjType_VNode_AARCH64_l0);
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate L0 page table in parent's CSpace: %s\n", err_getstring(err));
        return err;
    }
    printf("L0 page table created in parent\n");

    // Copy the L0 page table capability to the child’s CSpace
    struct capref child_l0_pt = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_PAGECN],
        .slot = PAGECN_SLOT_VROOT
    };


    // Initialize the child paging state with the L0 page table capability
    err = paging_init_state(child_paging_state, VADDR_OFFSET, si->l0pagetable, get_default_slot_allocator());
    if (err_is_fail(err)) {
        debug_printf("Failed to initialize child paging state: %s\n", err_getstring(err));
        return err;
    }
    printf("Child paging state initialized\n");

    err = cap_copy(child_l0_pt, si->l0pagetable);
    if (err_is_fail(err)) {
        debug_printf("Failed to copy L1 page table capability to child's CSpace: %s\n", err_getstring(err));
        return err;
    }

    struct paging_state *current_si = get_current_paging_state();
    si->childl0_pagetable = child_l0_pt;
    si->paging_state = child_paging_state;
    printf("Current Paging State:\n");
    printf("Start VAddr: %p\n", (void *)current_si->start_vaddr);
    printf("Current VAddr: %p\n", (void *)current_si->current_vaddr);
    printf("Root Table Cap: %d, %d\n", current_si->root->cap.cnode, current_si->root->cap.slot);

    // Assuming `si->childl0_pagetable` is already set up and refers to the L0 pagetable of the child
    // printf("Child Paging State:\n");
    // printf("Start VAddr: %p\n", si-childl0_pagetable->start_vaddr);
    // printf("Current VAddr: %p\n", (void *)si->childl0_pagetable->current_vaddr);
    // printf("Root Table Cap: %d, %d\n", si->childl0_pagetable->root->cap.cnode, si->childl0_pagetable->root->cap.slot);

    printf("L0 Page Table Cap: %d, %d\n", si->childl0_pagetable.cnode, si->childl0_pagetable.slot);

    printf("L1 page table copied to child's CSpace\n");
    return SYS_ERR_OK;
}

// allocate function for elf
// allocate function for elf
errval_t allocate_child_frame(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret) {
    size_t offset = BASE_PAGE_OFFSET(base);
    base -= offset;
    size = ROUND_UP(size + offset, BASE_PAGE_SIZE);

    struct capref frame;
    size_t sizeholder;
    frame_alloc(&frame, size, &sizeholder);


    paging_map_fixed_attr(state, base, frame, size, flags);
    printf("MAPPED CHILD SPACE ELF");
    
    paging_map_frame(get_current_paging_state(),ret,size,frame);
    printf("MAPPED PARENT SPACE ELF");
    *ret += offset;

    
    printf("ret (mapped address): %p\n", *ret);
    printf("Offset (alignment difference): %lu\n", offset);

    return SYS_ERR_OK; 
    }

// setup dispatcher function
static errval_t setup_dispatcher(struct spawninfo *si)
{
    errval_t err;

    // Allocate slot for dispatcher capability
    err = slot_alloc(&si->dispatcher_cap);
    printf("Slot allocated for dispatcher capability.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate slot for dispatcher capability: %s\n", err_getstring(err));
        return err;
    }

    err = dispatcher_create(si->dispatcher_cap);
    printf("Dispatcher created.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to create dispatcher: %s\n", err_getstring(err));
        return err;
    }

    // Allocate and retype endpoint
    struct capref dispatcher_endpoint;
    err = slot_alloc(&dispatcher_endpoint);
    printf("Slot allocated for endpoint.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate slot for endpoint: %s\n", err_getstring(err));
        return err;
    }

    err = cap_retype(dispatcher_endpoint, si->dispatcher_cap, 0, ObjType_EndPointLMP, 0);
    printf("Endpoint retyped.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to retype endpoint: %s\n", err_getstring(err));
        return err;
    }

    // Create dispatcher frame capability
    size_t retsize;
    err = frame_alloc(&si->dispatcher_frame_cap, DISPATCHER_FRAME_SIZE, &retsize);
    printf("Dispatcher frame capability created.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to allocate dispatcher frame: %s\n", err_getstring(err));
        return err;
    }

    // Copy capabilities to child space
    struct capref dispatcher_child = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_DISPATCHER
    };
    cap_copy(dispatcher_child, si->dispatcher_cap);
    printf("Dispatcher capability copied to child space.\n");

    struct capref selfep = {
        .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
        .slot = TASKCN_SLOT_SELFEP
    };
    cap_copy(selfep, dispatcher_endpoint);
    printf("Self endpoint copied to child space.\n");

    // struct capref dispatcher_frame_child = {
    //     .cnode = si->l2_cnodes[ROOTCN_SLOT_TASKCN],
    //     .slot = TASKCN_SLOT_DISPFRAME  
    // };
    // cap_copy(dispatcher_frame_child, si->dispatcher_frame_cap);
    printf("Dispatcher frame copied to child space.\n");

    // Map dispatcher into child VSpace
    void* vaddr_child;
    err = paging_map_frame(si->paging_state, &vaddr_child, DISPATCHER_FRAME_SIZE, si->dispatcher_frame_cap);
    printf("Dispatcher mapped into child space.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to map dispatcher frame to child space: %s\n", err_getstring(err));
        return err;
    }


    // Map dispatcher into parent space
    void* parent_vaddr_for_dispatch;
    err = paging_map_frame(get_current_paging_state(), &parent_vaddr_for_dispatch, DISPATCHER_FRAME_SIZE, si->dispatcher_frame_cap);
    printf("Dispatcher mapped into parent space.\n");
    if (err_is_fail(err)) {
        debug_printf("Failed to map dispatcher frame to parent space: %s\n", err_getstring(err));
        return err;
    }

    si->dispatcher_handle = (dispatcher_handle_t) parent_vaddr_for_dispatch;


    // Initialize dispatcher fields
    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(si->dispatcher_handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(si->dispatcher_handle);

    disp_gen->core_id = si->core_id;
    disp_gen->domain_id = si->core_id;
    disp->udisp = (lvaddr_t) vaddr_child;
    disp->disabled = 1;
    strncpy(disp->name, "ABDEL DEBUGGING DISPATCHER", DISP_NAME_LEN);
    printf("Dispatcher fields initialized.\n");

    // Get .got section for setting registers
    struct Elf64_Shdr* got_shdr = elf64_find_section_header_name(si->mapped_elf, si->child_frame_id.bytes, ".got");
    if (!got_shdr) {
        debug_printf("Failed to find .got section\n");
        return SPAWN_ERR_LOAD;
    }
    lvaddr_t got_addr = got_shdr->sh_addr;
    printf("GOT section found at address: 0x%lx\n", got_addr);

    // Set the registers including the GOT base
    armv8_set_registers(si->dispatcher_handle, si->entry_addr, got_addr);
    printf("Dispatcher registers set with entry: 0x%lx and GOT base: 0x%lx\n", si->entry_addr, got_addr);

    printf("Dispatcher setup completed successfully.\n");
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
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
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
    (void)si;

    // TODO:
    //  - check whether the process is in the right state
    //  - resume the execution of the process
    //  - set the state to running
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)si;

    // TODO:
    //  - check whether the process is in the right state
    //  - stop the execution of the process
    //  - set the state to suspended
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)si;

    // TODO:
    //  - check whether the process is in the right state
    //  - stop the execution of the process
    //  - set the state to killed
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)si;
    (void)ws;
    (void)handler;

    // TODO:
    //  - initialize the messaging channels for the process
    //  - check its execution state (it shouldn't have run yet)
    //  - create the required capabilities if needed
    //  - set the receive handler
    USER_PANIC("Not implemented");
    return LIB_ERR_NOT_IMPLEMENTED;
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