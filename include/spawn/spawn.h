/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_SPAWN_H_
#define _LIB_SPAWN_H_ 1

#include <barrelfish_kpi/types.h>
#include <aos/aos_rpc.h>




// forward declarations
struct elfimg;
struct bootinfo;
struct waitset;

/**
 * @brief represents the state of the process
 */
typedef enum spawnstate {
    SPAWN_STATE_UNKNOWN = 0,  ///< unknown state
    SPAWN_STATE_SPAWNING,     ///< process is being constructed
    SPAWN_STATE_READY,        ///< process is ready to run for the first time (hasn't run yet)
    SPAWN_STATE_RUNNING,      ///< process is running
    SPAWN_STATE_SUSPENDED,    ///< process is stopped, but has been running before
    SPAWN_STATE_KILLED,       ///< process has been killed
    SPAWN_STATE_TERMINATED,   ///< process has terminated (exited normally)
    SPAWN_STATE_CLEANUP,      ///< process is being cleaned up
} spawn_state_t;


struct spawninfo {
    /// name of the binary this process runs
    char *binary_name;

    /// the full commandline of this process, including its arguments
    char *cmdline;

    /// PID of this process
    domainid_t pid;

    /// execution state of this process
    spawn_state_t state;

    /// exit code of this process, or zero if it hasn't exited yet
    int exitcode;

    // MAPPING ELF TOOLS
    struct frame_identity child_frame_id;
    lvaddr_t mapped_elf;
    genvaddr_t entry_addr;
    struct mem_region *module;              ///< Program entry point


    // L1 CNODE REPRESENTING CSPACE
    struct capref l1_cap;
    struct cnoderef l1_cnode;
    struct cnoderef l2_cnodes[ROOTCN_SLOTS_USER];
    struct capref selfep_cap;
    struct capref argspage_cap;
    struct capref earlymem_cap;
    struct capref pagecn_cap;


    // VSPACE STUFF
    struct capref l0pagetable;
    struct capref childl0_pagetable;
    struct paging_state *paging_state;
    struct single_slot_allocator single_slot_alloc;

    // DISPATCHER STUFF:
    dispatcher_handle_t handle;

    struct capref dispframe_parent;
    struct capref dispatcher_parent;
    struct capref dispframe_child;
    struct capref dispatcher_child;


    // list of children processes (if this process spawns children)
    struct spawninfo **children;
    size_t num_children;

};


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
                                  domainid_t pid);

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
                              const char *argv[], int capc, struct capref caps[], domainid_t pid);

errval_t allocate_child_frame(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret);

/**
 * @brief constructs a new process by loading the image from the provided module
 *
 * @param[in] si    spawninfo structure to fill in
 * @param[in] img   pointer to the elf image in memory
 * @param[in] argc  number of arguments in argv
 * @param[in] argv  command line arguments
 * @param[in] pid   the process id (PID) for the new process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note, this function prepares a new process for running, but it does not make it
 * runnable. See spawn_start().
 */
static inline errval_t spawn_load_with_args(struct spawninfo *si, struct elfimg *img, int argc,
                                            const char *argv[], domainid_t pid)
{
    return spawn_load_with_caps(si, img, argc, argv, 0, NULL, pid);
}

/**
 * @brief starts the execution of the new process by making it runnable
 *
 * @param[in] si   spawninfo structure of the constructed process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_start(struct spawninfo *si);

/**
 * @brief resumes the execution of a previously stopped process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_resume(struct spawninfo *si);

/**
 * @brief stops (suspends) the execution of a running process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_suspend(struct spawninfo *si);

/**
 * @brief kills the execution of a running process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_kill(struct spawninfo *si);

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
errval_t spawn_exit(struct spawninfo *si, int exitcode);

/**
 * @brief cleans up the resources of a process
 *
 * @param[in] si   spawninfo structure of the process
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: The process has to be stopped before calling this function.
 */
errval_t spawn_cleanup(struct spawninfo *si);

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
errval_t spawn_setup_ipc(struct spawninfo *si, struct waitset *ws, aos_recv_handler_fn handler);

/**
 * @brief sets the receive handler function for the message channel
 *
 * @param[in] si       spawninfo structure of the process
 * @param[in] handler  handler function to be set
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 */
errval_t spawn_set_recv_handler(struct spawninfo *si, aos_recv_handler_fn handler);

#endif /* _LIB_SPAWN_H_ */