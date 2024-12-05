/*
 * Copyright (c) 2022 The University of British Columbia
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

/**
 * @file
 * @brief Interface for managing processes
 *
 * This file contains the process manager. It has basically the same interface as the
 * process manager client (see include/proc_mgmt/proc_mgmt.h). And a few additional functions
 */

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <spawn/spawn.h>
#include <spawn/multiboot.h>
#include <spawn/elfimg.h>
#include <spawn/argv.h>

#include "proc_mgmt.h"
#include <proc_mgmt/proc_mgmt.h>

extern struct bootinfo *bi;
extern coreid_t         my_core_id;
struct process_manager *proc_manager;
struct spawninfo* root = NULL;

static errval_t parse_args(const char *cmdline, int *argc, char *argv[]);

/*
 * ------------------------------------------------------------------------------------------------
 * Utility Functions
 * ------------------------------------------------------------------------------------------------
 */

__attribute__((__used__)) static void spawn_info_to_proc_status(struct spawninfo   *si,
                                                                struct proc_status *status)
{
    status->core      = my_core_id;
    status->pid       = si->pid;
    status->exit_code = 0;
    strncpy(status->cmdline, si->cmdline, sizeof(status->cmdline));
    switch (si->state) {
    case SPAWN_STATE_SPAWNING:
        status->state = PROC_STATE_SPAWNING;
        break;
    case SPAWN_STATE_READY:
        status->state = PROC_STATE_SPAWNING;
        break;
    case SPAWN_STATE_RUNNING:
        status->state = PROC_STATE_RUNNING;
        break;
    case SPAWN_STATE_SUSPENDED:
        status->state = PROC_STATE_PAUSED;
        break;
    case SPAWN_STATE_KILLED:
        status->state     = PROC_STATE_KILLED;
        status->exit_code = -1;
        break;
    case SPAWN_STATE_TERMINATED:
        status->state     = PROC_STATE_EXITED;
        status->exit_code = si->exitcode;
        break;
    default:
        status->state = PROC_STATE_UNKNOWN;
    }
}

void initialize_process_manager(struct process_manager ** pm);
struct process_node * allocate_process_node(struct process_manager *manager);

struct process_node * allocate_process_node(struct process_manager *manager) {
    printf("get in allocate pm node\n");
    if (manager->head == NULL) {
        printf("get in allocate_process_node when head null\n");
        manager->head = malloc(sizeof(struct process_node));
        manager->head->si = malloc(sizeof(struct spawninfo));
        manager->head->next = NULL;
        manager->head->processes = malloc(sizeof(struct proc_status));
        printf("getting out allocate_process_node when head null\n");
        return manager->head;
    } else {
         printf("head is not null\n");
        struct process_node * curr = manager->head;
        while(curr->next!=NULL) {
            curr = curr->next;
        }
        curr->next = malloc(sizeof(struct process_node));
        curr->next->si = malloc(sizeof(struct spawninfo));
        curr->next->next = NULL;
        curr->next->processes = malloc(sizeof(struct proc_status));
        return curr->next;

    }
}

void initialize_process_manager(struct process_manager ** pm) {
    if (*pm == NULL) {
        *pm = malloc(sizeof(struct process_manager));
    if (*pm == NULL) {
        printf("Failed to allocate memory for process manager\n");
        return; // Handle memory allocation failure if needed
    }

    (*pm)->next_pid = 0;
    (*pm)->num_processes = 0;
    (*pm)->head = NULL;

    printf("Initialization successful\n");
    } else {
        printf("shouldn't init\n");
    }
    
}


/*
 * ------------------------------------------------------------------------------------------------
 * Spawning a new process
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief spawns a new process with the given arguments and capabilities on the given core.
 *
 * @param[in]  argc  the number of arguments expected in the argv array
 * @param[in]  argv  array of null-terminated strings containing the arguments
 * @param[in]  capc  the number of capabilities to pass to the new process
 * @param[in]  capv  array of capabilitiies to pass to the child
 * @param[in]  core  id of the core to spawn the program on
 * @param[out] pid   returned program id (PID) of the spawned process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: concatenating all values of argv into a single string should yield the
 * command line of the process to be spawned.
 */
errval_t proc_mgmt_spawn_with_caps(int argc, const char *argv[], int capc, struct capref capv[],
                                   coreid_t core, domainid_t *pid)
{
    // make compiler happy about unused parameters
    (void)argc;
    (void)argv;
    (void)capc;
    (void)capv;
    (void)core;
    (void)pid;

    // TODO:
    //  - find the image
    //  - allocate a PID
    //  - use the spawn library to construct a new process
    //  - start the new process
    //  - keep track of the spawned process
    //
    // Note: With multicore support, you many need to send a message to the other core
    errval_t err;
    initialize_process_manager(&proc_manager);
    *pid =  allocate_pid(proc_manager);
    struct process_node *pro_node=  allocate_process_node(proc_manager);
    printf("successful allocate pro_node\n");
    pro_node->processes->core = core;
    pro_node->processes->pid = *pid;
    pro_node->processes->state = PROC_STATE_SPAWNING;
    pro_node->processes->exit_code = 0;
     printf("allocate new PID in spawn with caps%u\n", *pid);

    pro_node->si->binary_name = malloc(strlen((char*)argv[0]) + 1);
    pro_node->name = malloc(strlen((char*)argv[0]) + 1);
    printf("after malloc%u\n", *pid);


    strcpy(pro_node->si->binary_name, (char*) argv[0]);
        printf("after strcpy%u\n", *pid);


    
    struct mem_region* module = multiboot_find_module(bi, argv[0]);
    if (module == NULL) {
        debug_printf("multiboot_find_module failed to find %s\n", argv[0]);
        return SPAWN_ERR_FIND_MODULE;
    }

    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = module->mrmod_slot,
    };
    // - Map multiboot module in your address space
    struct frame_identity child_frame_id;
    err = frame_identify(child_frame, &child_frame_id);
    if (err_is_fail(err)) {
        USER_PANIC("spawn_load_with_caps err\n");
    }
    lvaddr_t mapped_elf;
    err = paging_map_frame(get_current_paging_state(), (void**)&mapped_elf,
                           module->mrmod_size, child_frame);
    
    if (err_is_fail(err)) {
        USER_PANIC("spawn_load_with_caps err\n");
    }

    pro_node->si->module = module;
    pro_node->si->child_frame_id = child_frame_id;
    pro_node->si->mapped_elf = mapped_elf;
    pro_node->si->pid = *pid;
    pro_node->si->nextSpawn = root;

    struct elfimg img;
    elfimg_init_from_module(&img, module);

    err = spawn_load_with_caps(pro_node->si, &img, argc, argv, capc, capv, *pid);
    if (err_is_fail(err)) {
        USER_PANIC("spawn_load_with_caps err\n");
    }
    pro_node->si->state =  SPAWN_STATE_READY;

    err = spawn_start(pro_node->si);
    if (err_is_fail(err)) {
        USER_PANIC("spawn_load_with_caps err in spawn_start: %s\n", err_getstring(err));
    }

    return SYS_ERR_OK;

    
}

/**
 * @brief function to allocate a unique PID for each process
 */
domainid_t allocate_pid(struct process_manager *manager) {
    
    if (manager->next_pid == 0) {
        // Avoid returning 0 as a PID, which may represent an invalid state
        manager->next_pid++;
    }
    return manager->next_pid++;
}



/**
 * @brief spawns a new process with the given commandline arguments on the given core
 *
 * @param[in]  cmdline  commandline of the programm to be spawned
 * @param[in]  core     id of the core to spawn the program on
 * @param[out] pid      returned program id (PID) of the spawned process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this function should replace the default commandline arguments the program.
 */
errval_t proc_mgmt_spawn_with_cmdline(const char *cmdline, coreid_t core, domainid_t *pid) {
    // Ensure valid parameters
    // Handle multicore spawning
    if (core != my_core_id) {
        debug_printf("Spawning on core %d from core %d\n", core, my_core_id);

        // Select appropriate UMP channel for inter-core communication
        /**
         *  get_channel_for_core_to_monitor(core, 1) gets the monitor-to-core channel (used by the BSP).
            get_channel_for_current_core(0) gets the current-core-to-monitor channel (used by application cores).
         */
        struct ump_chan *uchan = (my_core_id == 0) ? get_channel_for_core_to_monitor(core, 1) : get_channel_for_current_core(0);

        // Construct UMP payload message
        struct ump_payload msg;
        msg.type = SPAWN_CMDLINE;
        msg.core = core;

        // Safely copy command line into the payload (respecting payload size limits)
        strncpy(msg.payload, cmdline, sizeof(msg.payload) - sizeof(enum msg_type) - sizeof(coreid_t));
        msg.payload[sizeof(msg.payload) - 1] = '\0';  // Ensure null-termination

        // Send the message
        errval_t err = ump_send(uchan, (char *)&msg, sizeof(struct ump_payload));
        if (err_is_fail(err)) {
            debug_printf("Failed to send UMP message: %s\n", err_getstring(err));
            return err;
        }

        // TODO: Block and wait for acknowledgment from the other core (e.g., using UMP receive)

        return SYS_ERR_OK;
    }

    printf("reach before args\n");
    // Parse the command line into arguments
    const char *argv[MAX_CMDLINE_ARGS];
    argv[0] = cmdline;
    int argc = 0;
    printf("reach before parse args\n");

    parse_args(cmdline, &argc, (char **)argv);
    printf("reach after parse args\n");


    // Spawn the process with parsed arguments
    return proc_mgmt_spawn_with_caps(argc, argv, 0, NULL, core, pid);
    return SYS_ERR_OK;
}


/**
 * @brief Splits a command line string into an array of arguments.
 *
 * @param[in]  cmdline  The command line string to parse.
 * @param[out] argc     The number of arguments parsed.
 * @param[out] argv     The array of argument strings.
 */
static errval_t parse_args(const char *cmdline, int *argc, char *argv[])
{
    // check if we have at least one argument
    if (argv == NULL || argv[0] == NULL || argc == NULL || cmdline == NULL) {
        return CAPS_ERR_INVALID_ARGS;
    }

    // parse cmdline, split on spaces
    char cmdline_ptr[MAX_CMDLINE_ARGS + 1];
    strncpy(cmdline_ptr, cmdline, strlen(cmdline) + 1);
    char *token = strtok(cmdline_ptr, " ");
    int i = 0;
    *argc = 0;

    while (token != NULL && i < MAX_CMDLINE_ARGS) {
        argv[i++] = token;
        (*argc)++;
        token = strtok(NULL, " ");
    }
    argv[i] = NULL;

    return SYS_ERR_OK;
}

/**
 * @brief spawns a new process with the default arguments on the given core
 *
 * @param[in]  path  string containing the path to the binary to be spawned
 * @param[in]  core  id of the core to spawn the program on
 * @param[out] pid   returned program id (PID) of the spawned process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this function should spawn the program with the default arguments as
 *       listed in the menu.lst file.
 */
errval_t proc_mgmt_spawn_program(const char *path, coreid_t core, domainid_t *pid)
{
    (void) core;
    // Initialize `spawninfo` structure
    //struct spawninfo si;

    printf("si initialized");
    struct mem_region *module = multiboot_find_module(bi, path);
    const char *cmdline = multiboot_module_opts(module);


    // Call spawn_load_with_bootinfo to load the process
    printf("Calling spawn_load_with_bootinfo for PID %u\n", *pid);
    // si.core_id = my_core_id;
    initialize_process_manager(&proc_manager);
    *pid =  allocate_pid(proc_manager);
    struct process_node *pro_node=  allocate_process_node(proc_manager);
    pro_node->processes->core = core;
    pro_node->processes->pid = *pid;
    pro_node->processes->state = PROC_STATE_SPAWNING;
    pro_node->processes->exit_code = 0;
    pro_node->name = cmdline;


    errval_t err = spawn_load_with_bootinfo(pro_node->si, bi, cmdline, *pid);
    if (err_is_fail(err)) {
        debug_printf("Error loading process: %s\n", err_getstring(err));
        return err;
    }
    printf("Process loaded successfully for PID %u\n", *pid);
    
    pro_node->si->state = SPAWN_STATE_READY;
    err = spawn_start(pro_node->si);
    if (err_is_fail(err)) {
        debug_printf("Error Starting process: %s\n", err_getstring(err));
        return err;
    }
    printf("Process running successfully for PID %u\n", *pid);


    return SYS_ERR_OK;
}


/*
 * ------------------------------------------------------------------------------------------------
 * Listing of Processes
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief obtains the statuses of running processes from the process manager
 *
 * @param[out] ps    array of process status in the system (must be freed by the caller)
 * @param[out] num   the number of processes in teh list
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: the caller is responsible for freeing the array of process statuses.
 *       note: you may use the combination of the functions below to implement this one.
 */
errval_t proc_mgmt_ps(struct proc_status **ps, size_t *num)
{
    // make compiler happy about unused parameters
    (void)ps;
    (void)num;

    
    // TODO:
    //  - consult the process table to obtain the status of the processes
    // Ensure the process manager and head of the list are initialized
    if (proc_manager == NULL || proc_manager->head == NULL) {
        printf("Process manager not initialized or no processes in the list\n");
        *ps = NULL;
        *num = 0;
        return SPAWN_ERR_FIND_SPAWNDS;  // Return an error if no processes are found
    }

    // First pass: Count the number of processes in the list
    size_t count = 0;
    struct process_node *current = proc_manager->head;
    while (current != NULL) {
        spawn_info_to_proc_status(current->si, current->processes);
        count++;
        current = current->next;
    }

    // Allocate memory for the array of process statuses
    *ps = malloc(count * sizeof(struct proc_status));
    if (*ps == NULL) {
        printf("Memory allocation for process status array failed\n");
        *num = 0;
        return SPAWN_ERR_FIND_SPAWNDS;
    }

    // Second pass: Populate the array with each process's status
    current = proc_manager->head;
    size_t index = 0;
    while (current != NULL) {

        (*ps)[index].core = current->processes->core;
        (*ps)[index].pid = current->processes->pid;
        (*ps)[index].state = current->processes->state;
        (*ps)[index].exit_code = current->processes->exit_code;
        strncpy((*ps)[index].cmdline, current->processes->cmdline, sizeof((*ps)[index].cmdline));
        index++;
        current = current->next;
    }

    // Set the number of processes
    *num = count;

    return SYS_ERR_OK;  // Indicate success
}


/**
 * @brief obtains the list of running processes from the process manager
 *
 * @param[out] pids  array of process ids in the system (must be freed by the caller)
 * @param[out] num   the number of processes in teh list
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: the caller is responsible for freeing the array of process ids.
 */
errval_t proc_mgmt_get_proc_list(domainid_t **pids, size_t *num)
{
    // make compiler happy about unused parameters
    (void)pids;
    (void)num;

    struct process_node *curr = proc_manager->head;
    size_t count = 0;

    if (curr == NULL) {
        return SPAWN_ERR_FIND_SPAWNDS;
    }
    while (curr!= NULL) {
        spawn_info_to_proc_status(curr->si,curr->processes);
        if (curr->processes->state == PROC_STATE_RUNNING) {
            count++;
        }
        curr = curr->next;
    }

     while (curr != NULL) {
        spawn_info_to_proc_status(curr->si, curr->processes);
        if (curr->processes->state == PROC_STATE_RUNNING) {
            count++;
        }
        curr = curr->next;
    }

    // Allocate memory for the list of PIDs
    *pids = malloc(count * sizeof(domainid_t));
    if (*pids == NULL) {
        return SPAWN_ERR_FIND_SPAWNDS; // Return an error if memory allocation fails
    }

    // Reset the iterator and populate the PID list
    curr = proc_manager->head;
    size_t index = 0;
    while (curr != NULL) {
        spawn_info_to_proc_status(curr->si, curr->processes);
        if (curr->processes->state == PROC_STATE_RUNNING) {
            (*pids)[index++] = curr->processes->pid;
        }
        curr = curr->next;
    }

    // Set the number of running processes
    *num = count;

    return SYS_ERR_OK;
    
    // TODO:
    //  - consult the process table to obtain a list of PIDs of the processes in the system

}


/**
 * @brief obtains the PID for a process name
 *
 * @param[in]  name  name of the process to obtain the PID for
 * @param[out] pid   returned program id (PID) of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: Names that are an absoute path should match precisely on the full path.
 *       Names that just include the binary name may match all processes with the
 *       same name. If there are multiple matches
 */
errval_t proc_mgmt_get_pid_by_name(const char *name, domainid_t *pid)
{
    // make compiler happy about unused parameters
    (void)name;
    (void)pid;

    // TODO:
    //   - lookup the process with the given name in the process table
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief obtains the status of a process with the given PID
 *
 * @param[in] pid
 * @param[out] status
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_get_status(domainid_t pid, struct proc_status *status)
{
    // Check if proc_manager and the head of the list are initialized
    if (proc_manager == NULL || proc_manager->head == NULL) {
        printf("Process manager not initialized or no processes in the list\n");
        return SPAWN_ERR_FIND_SPAWNDS;  // Return an error if no processes are found
    }

    // Traverse the linked list of processes
    struct process_node *current = proc_manager->head;
    while (current != NULL) {
        // Check if the full command line matches
        spawn_info_to_proc_status(current->si, current->processes);
        if (current->processes->pid == pid) {
            // Process with the given PID found, populate the status struct
            status->core = current->processes->core;
            status->pid = current->processes->pid;
            status->state = current->processes->state;
            status->exit_code = current->processes->exit_code;
            strncpy(status->cmdline, current->processes->cmdline, sizeof(status->cmdline));

            return SYS_ERR_OK;  // Successfully found and populated the status
        }

        current = current->next;
    }

    // Process with the given PID was not found
    printf("Process with PID %u not found\n", pid);
    return SPAWN_ERR_FIND_SPAWNDS;  // Return an error indicating the PID was not found
}


/**
 * @brief obtains the name of a process with the given PID
 *
 * @param[in] did   the PID of the process
 * @param[in] name  buffer to store the name in
 * @param[in] len   length of the name buffer
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_get_name(domainid_t pid, char *name, size_t len)
{
    // make compiler happy about unused parameters
    (void)pid;
    (void)name;
    (void)len;


    // TODO:
    //   - get the name of the process with the given PID
     // Check if the process manager and head of the list are initialized
    if (proc_manager == NULL || proc_manager->head == NULL) {
        printf("Process manager not initialized or no processes in the list\n");
        name = NULL;
        return SYS_ERR_OK;  // Return an error if no processes are found
    }

    // Traverse the linked list of processes
    struct process_node *current = proc_manager->head;
    while (current != NULL) {
        spawn_info_to_proc_status(current->si, current->processes);
        // Check if the PID matches
        if (current->si->pid == pid) {
            // Found the process, copy its name to the buffer
            strncpy(name, current->si->cmdline, len - 1);
            name[len - 1] = '\0';  // Ensure null termination

            return SYS_ERR_OK;  // Successfully found and copied the name
        }
        current = current->next;
    }

    // Process with the given PID was not found
    printf("Process with PID %u not found\n", pid);
    name = NULL;
    return SYS_ERR_OK;
}


/*
 * ------------------------------------------------------------------------------------------------
 * Pausing and Resuming of Processes
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief pauses the execution of a process
 *
 * @param[in] pid  the PID of the process to pause
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_suspend(domainid_t pid)
{
    struct process_node *current = proc_manager->head;
    struct process_node *prev = NULL;

    while (current != NULL) {
        if (current->si->pid == pid) {
            // Attempt to suspend the process
            errval_t err = spawn_suspend(current->si);
            if (err_is_fail(err)) {
                USER_PANIC("Failed to SUSPEND process with PID %d: %s\n", pid, err_getstring(err));
                return err;
            }
            
            // Mark the process state as suspended
            current->si->state = SPAWN_STATE_SUSPENDED;
            printf("STATE OF CURRENT: %d\n", current->si->state);
            return SYS_ERR_OK;
        }
        prev = current;
        current = current->next;
    }

    return SPAWN_ERR_DOMAIN_NOTFOUND;  // If PID not found, return an appropriate error
}


/**
 * @brief resumes the execution of a process
 *
 * @param[in] pid  the PID of the process to resume
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_resume(domainid_t pid)
{
    struct process_node *current = proc_manager->head;
    struct process_node *prev = NULL;

    while (current != NULL) {
        if (current->si->pid == pid) {
            // Attempt to suspend the process
            errval_t err = spawn_resume(current->si);
            if (err_is_fail(err)) {
                USER_PANIC("Failed to SUSPEND process with PID %d: %s\n", pid, err_getstring(err));
                return err;
            }
            
            // Mark the process state as suspended
            current->si->state = SPAWN_STATE_RUNNING;
            printf("STATE OF CURRENT: %d\n", current->si->state);
            return SYS_ERR_OK;
        }
        prev = current;
        current = current->next;
    }

    return SPAWN_ERR_DOMAIN_NOTFOUND;  // If PID not found, return an appropriate error
}


/*
 * ------------------------------------------------------------------------------------------------
 * Termination of a Process
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief tells the process manager that the calling process terminated with the given status
 *
 * @param[in] status  integer value with the given status
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this function should not be called by the process directly, but from the exit code
 *       when main returns. Moreover, the function should make sure that the process is
 *       no longer scheduled. The status is the return value of main(), or the error value
 *       e.g., page fault or alike.
 */
errval_t proc_mgmt_exit(int status)
{
    // make compiler happy about unused parameters
    (void)status;

    USER_PANIC("should not be called by the process manager\n");
    return SYS_ERR_OK;
}

/**
 * @brief tells the process manager than the process with pid has terminated.
 *
 * @param[in] pid     process identifier of the process to wait for
 * @param[in] status  integer value with the given status
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this means the process has exited gracefully
 */
errval_t proc_mgmt_terminated(domainid_t pid, int status)
{
    // make compiler happy about unused parameters
    (void)pid;
    (void)status;

    //USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - find the process with the given PID and trigger the exit procedure
    //   - remove the process from the process table
    //   - clean up the state of the process
    //   - for M4: notify waiting processes
    debug_printf("enter proc_mgmt_terminated\n");
    struct process_node * curr = proc_manager->head;
    while (curr != NULL) {
        if (curr->si->pid == pid) {
            curr->si->exitcode = status;
             errval_t err = proc_mgmt_kill(pid);
            if(err_is_fail(err)) {
                USER_PANIC("process is not successfully terminated\n");
            }
            curr->si->state = SPAWN_STATE_TERMINATED;
           
    
            debug_printf("Process manager knows pid: %d, terminated\n");
            return SYS_ERR_OK;
        }
        curr = curr->next;
    }

    return SPAWN_ERR_DOMAIN_NOTFOUND;
    //return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief waits for a process to have terminated
 *
 * @param[in]  pid     process identifier of the process to wait for
 * @param[out] status  returns the status of the process as set by `proc_mgmt_exit()`
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_wait(domainid_t pid, int *status)
{
    // make compiler happy about unused parameters
    (void)pid;
    (void)status;

    USER_PANIC("should not be called by the process manager\n");
    return SYS_ERR_OK;
}


 /**
  * @brief registers a channel to be triggered when the process exits
 *
 * @param[in] pid   the PID of the process to register a trigger for
 * @param[in] t     channel type
 * @param[in] chan  channel to be triggered
 * @param[in] ws    the waitset to be used for the channel
 * 
 * @return SYS_ERR_OK on sucess, SPANW_ERR_* on failure
 */ 
errval_t proc_mgmt_register_wait(domainid_t pid, enum aos_rpc_transport t, void *chan,
                                 struct waitset *ws)
{

    (void)pid;
    (void)t;
    (void)chan;
    (void)ws;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - find the process with the given PID register the channel for notification
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief terminates the process with the given process id
 *
 * @param[in] pid  process identifier of the process to be killed
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t proc_mgmt_kill(domainid_t pid)
{
    struct process_node *current = proc_manager->head;
    struct process_node *prev = NULL;

    while (current != NULL) {
        if (current->si->pid == pid) {
            // Attempt to kill the process
            
            errval_t err = spawn_kill(current->si);
            if (err_is_fail(err)) {
                USER_PANIC("Failed to kill process with PID %d: %s\n", pid, err_getstring(err));
                return err;
            }
            
            // Mark the process state as killed
            current->si->state = SPAWN_STATE_KILLED;
            current->si->exitcode = -1;  // Standard exit code for killed process

            // Remove the node from the linked list
            if (prev == NULL) {
                proc_manager->head = current->next;  // Head is being removed
            } else {
                prev->next = current->next;  // Bypass the current node
            }
            
            // Free the node resources if necessary
            free(current->si);  // Free spawn info if needed
            free(current);      // Free the node itself
            
            // Decrease the count of processes
            proc_manager->num_processes--;
            
            return SYS_ERR_OK;
        }
        prev = current;
        current = current->next;
    }

    return SPAWN_ERR_DOMAIN_NOTFOUND;  // If PID not found, return an appropriate error
}
    // TODO:
    //  - find the process in the process table and kill it
    //   - remove the process from the process table
    //   - clean up the state of the process
    //   - M4: notify its waiting processes




/**
 * @brief terminates all processes that match the given name
 *
 * @param[in] name   null-terminated string of the processes to be terminated
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * The all processes that have the given name should be terminated. If the name is
 * an absolute path, then there must be an exact match. If the name only contains the
 * binary name, then any processes with the same binary name should be terminated.
 *
 * Good students may implement regular expression matching for the name.
 */
errval_t proc_mgmt_killall(const char *name)
{
    struct process_node *current = proc_manager->head;
    struct process_node *prev = NULL;
    printf("PROC HEAD name: %s\n", current->si->binary_name);
    bool found = false;


    while (current != NULL) {
        if (strcmp(current->si->binary_name, name) == 0) {
            found = true;
            printf("input name: %s\n", name);
            printf("Current iteration name: %s\n", current->si->binary_name);
            // Attempt to kill the process
            errval_t err = spawn_kill(current->si);
            if (err_is_fail(err)) {
                USER_PANIC("Failed to kill process with NAME %d: %s\n", name, err_getstring(err));
                return err;
            }
            
            // Mark the process state as killed
            current->si->state = SPAWN_STATE_KILLED;
            current->si->exitcode = -1;  // Standard exit code for killed process

            // Remove the node from the linked list
            if (prev == NULL) {
                proc_manager->head = current->next;  // Head is being removed
            } else {
                prev->next = current->next;  // Bypass the current node
            }
            
            // Free the node resources if necessary
            free(current->si);  // Free spawn info if needed
            free(current);      // Free the node itself
            
            // Decrease the count of processes
            proc_manager->num_processes--;
            
        }
        prev = current;
        current = current->next;
    }

return found ? SYS_ERR_OK : SPAWN_ERR_DOMAIN_NOTFOUND;  // If no matching process was found, return an appropriate error
}
    // TODO:
    //  - find all the processs that match the given name
    //  - remove the process from the process table
    //  - clean up the state of the process
    //  - M4: notify its waiting processes

