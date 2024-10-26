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

extern struct bootinfo *bi;
extern coreid_t         my_core_id;





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

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - find the image
    //  - allocate a PID
    //  - use the spawn library to construct a new process
    //  - start the new process
    //  - keep track of the spawned process
    //
    // Note: With multicore support, you many need to send a message to the other core
    return LIB_ERR_NOT_IMPLEMENTED;
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
errval_t proc_mgmt_spawn_with_cmdline(const char *cmdline, coreid_t core, domainid_t *pid)
{
    // make compiler happy about unused parameters
    (void)cmdline;
    (void)core;
    (void)pid;

    // TODO:
    //  - find the image
    //  - allocate a PID
    //  - use the spawn library to construct a new process
    //  - start the new process
    //  - keep track of the spawned process
    // HINT: you may call proc_mgmt_spawn_with_caps with some preparation
    // Note: With multicore support, you many need to send a message to the other core
    USER_PANIC("functionality not implemented\n");
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)path;
    (void)core;
    (void)pid;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - find the image
    //  - allocate a PID
    //  - use the spawn library to construct a new process
    //  - start the new process
    //  - keep track of the spawned process
    //
    // Note: With multicore support, you many need to send a message to the other core
    return LIB_ERR_NOT_IMPLEMENTED;
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

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - consult the process table to obtain the status of the processes
    return LIB_ERR_NOT_IMPLEMENTED;
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

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - consult the process table to obtain a list of PIDs of the processes in the system
    return LIB_ERR_NOT_IMPLEMENTED;
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

    USER_PANIC("functionality not implemented\n");
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
    // make compiler happy about unused parameters
    (void)pid;
    (void)status;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - get the status of the process with the given PID
    return LIB_ERR_NOT_IMPLEMENTED;
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

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - get the name of the process with the given PID
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)pid;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - find the process with the given PID and suspend it
    return LIB_ERR_NOT_IMPLEMENTED;
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
    // make compiler happy about unused parameters
    (void)pid;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - find the process with the given PID and resume its execution
    return LIB_ERR_NOT_IMPLEMENTED;
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

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //   - find the process with the given PID and trigger the exit procedure
    //   - remove the process from the process table
    //   - clean up the state of the process
    //   - for M4: notify waiting processes
    return LIB_ERR_NOT_IMPLEMENTED;
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
 * @brief tells the process manager than the process with pid has terminated.
 *
 * @param[in] pid     process identifier of the process to wait for
 * @param[in] status  integer value with the given status
 *
 * @return SYS_ERR_OK on success, SPAWN_ERR_* on failure
 *
 * Note: this means the process has exited gracefully
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
    // make compiler happy about unused parameters
    (void)pid;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - find the process in the process table and kill it
    //   - remove the process from the process table
    //   - clean up the state of the process
    //   - M4: notify its waiting processes
    return LIB_ERR_NOT_IMPLEMENTED;
}


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
    // make compiler happy about unused parameters
    (void)name;

    USER_PANIC("functionality not implemented\n");
    // TODO:
    //  - find all the processs that match the given name
    //  - remove the process from the process table
    //  - clean up the state of the process
    //  - M4: notify its waiting processes
    return LIB_ERR_NOT_IMPLEMENTED;
}

