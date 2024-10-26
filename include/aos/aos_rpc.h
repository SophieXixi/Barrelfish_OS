/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * Copyright (c) 2022 The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>


/// defines the transport backend of the RPC channel
enum aos_rpc_transport {
    AOS_RPC_LMP,
    AOS_RPC_UMP,
};


/// type of the receive handler function.
/// depending on your RPC implementation, maybe you want to slightly adapt this
typedef void (*aos_recv_handler_fn)(struct aos_rpc *ac);




/**
 * @brief represents an RPC binding
 *
 * Note: the RPC binding should work over LMP (M4) or UMP (M6)
 */

struct aos_rpc {
    // TODO(M3): Add state
};

/**
 * @brief Initialize an aos_rpc struct.
 *
 * @param[in] rpc  The aos_rpc struct to initialize.
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_init(struct aos_rpc *rpc);






/*
 * ------------------------------------------------------------------------------------------------
 * AOS RPC: Init Channel
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief Send a single number over an RPC channel.
 *
 * @param[in] chan  the RPC channel to use  (init channel)
 * @param[in] val   the number to send
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 *
 * Channel: init
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);


/**
 * @brief Send a single number over an RPC channel.
 *
 * @param[in] chan  the RPC channel to use (init channel)
 * @param[in] val   the string to send
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 *
 * Channel: init
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);


/*
 * ------------------------------------------------------------------------------------------------
 * AOS RPC: Memory Channel
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief Request a RAM capability with >= bytes of size
 *
 * @param[in]  chan       the RPC channel to use (memory channel)
 * @param[in]  bytes      minimum number of bytes to request
 * @param[in]  alignment  minimum alignment of the requested RAM capability
 * @param[out] retcap     received capability
 * @param[out] ret_bytes  size of the received capability in bytes
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 *
 * Channel: memory
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes, size_t alignment,
                             struct capref *retcap, size_t *ret_bytes);


/*
 * ------------------------------------------------------------------------------------------------
 * AOS RPC: Serial Channel
 * ------------------------------------------------------------------------------------------------
 */


/**
 * @brief obtains a single character from the serial
 *
 * @param chan  the RPC channel to use (serial channel)
 * @param retc  returns the read character
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);


/**
 * @brief sends a single character to the serial
 *
 * @param chan  the RPC channel to use (serial channel)
 * @param c     the character to send
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);


/*
 * ------------------------------------------------------------------------------------------------
 * AOS RPC: Process Management
 * ------------------------------------------------------------------------------------------------
 */



/**
 * @brief requests a new process to be spawned with the supplied arguments and caps
 *
 * @param[in]  chan    the RPC channel to use (process channel)
 * @param[in]  argc    number of arguments in argv
 * @param[in]  argv    array of strings of the arguments to be passed to the new process
 * @param[in]  capc    the number of capabilities that are being sent
 * @param[in]  cap     capabilities to give to the new process, or NULL_CAP if none
 * @param[in]  core    core on which to spawn the new process on
 * @param[out] newpid  returns the PID of the spawned process
 *
 * @return SYS_ERR_OK on success, or error value on failure
 *
 * Hint: we should be able to send multiple capabilities, but we can only send one.
 *       Think how you could send multiple cappabilities by just sending one.
 */
errval_t aos_rpc_proc_spawn_with_caps(struct aos_rpc *chan, int argc, const char *argv[], int capc,
                                      struct capref cap, coreid_t core, domainid_t *newpid);


/**
 * @brief requests a new process to be spawned with the supplied commandline
 *
 * @param[in]  chan    the RPC channel to use (process channel)
 * @param[in]  cmdline  command line of the new process, including its args
 * @param[in]  core     core on which to spawn the new process on
 * @param[out] newpid   returns the PID of the spawned process
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_spawn_with_cmdline(struct aos_rpc *chan, const char *cmdline, coreid_t core,
                                         domainid_t *newpid);


/**
 * @brief requests a new process to be spawned with the default arguments
 *
 * @param[in]  chan     the RPC channel to use (process channel)
 * @param[in]  path     name of the binary to be spawned
 * @param[in]  core     core on which to spawn the new process on
 * @param[out] newpid   returns the PID of the spawned process
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_spawn_with_default_args(struct aos_rpc *chan, const char *path, coreid_t core,
                                              domainid_t *newpid);


/**
 * @brief obtains a list of PIDs of all processes in the system
 *
 * @param[in]  chan       the RPC channel to use (process channel)
 * @param[out] pids       array of PIDs of all processes in the system (freed by caller)
 * @param[out] pid_count  the number of PIDs in the list
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_get_all_pids(struct aos_rpc *chan, domainid_t **pids, size_t *pid_count);

/**
 * @brief obtains the status of a process
 *
 * @param[in]  chan         the RPC channel to use (process channel)
 * @param[in]  pid          PID of the process to get the status of
 * @param[out] core         core on which the process is running
 * @param[out] cmdline      buffer to store the cmdline in
 * @param[out] cmdline_max  size of the cmdline buffer in bytes
 * @param[out] state        returns the state of the process
 * @param[out] exit_code    returns the exit code of the process (if terminated)
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_get_status(struct aos_rpc *chan, domainid_t pid, coreid_t *core,
                                 char *cmdline, int cmdline_max, uint8_t *state, int *exit_code);


/**
 * @brief obtains the name of a process with a given PID
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] name  the name of the process to search for
 * @param[in] pid   returns PID of the process to pause/suspend
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_get_name(struct aos_rpc *chan, domainid_t pid, char *name, size_t len);


/**
 * @brief obtains the PID of a process with a given name
 *
 * @param[in]  chan  the RPC channel to use (process channel)
 * @param[in]  name  the name of the process to search for
 * @param[out] pid   returns PID of the process with the given name
 *
 * @return SYS_ERR_OK on success, or error value on failure
 *
 * Note: if there are multiple processes with the same name, the smallest PID should be
 * returned.
 */
errval_t aos_rpc_proc_get_pid(struct aos_rpc *chan, const char *name, domainid_t *pid);


/**
 * @brief pauses or suspends the execution of a running process
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to pause/suspend
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_pause(struct aos_rpc *chan, domainid_t pid);


/**
 * @brief resumes a previously paused process
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to resume
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_resume(struct aos_rpc *chan, domainid_t pid);


/**
 * @brief exists the current process with the supplied exit code
 *
 * @param[in] chan    the RPC channel to use (process channel)
 * @param[in] status  exit status code to send to the process manager.
 *
 * @return SYS_ERR_OK on success, or error value on failure
 *
 * Note: this function does not return, the process manager will halt the process execution.
 */
errval_t aos_rpc_proc_exit(struct aos_rpc *chan, int status);


/**
 * @brief waits for the process with the given PID to exit
 *
 * @param[in]  chan     the RPC channel to use (process channel)
 * @param[in]  pid      PID of the process to wait for
 * @param[out] status   returns the exit status of the process
 *
 * @return SYS_ERR_OK on success, or error value on failure
 *
 * Note: the RPC will only return after the process has exited
 */
errval_t aos_rpc_proc_wait(struct aos_rpc *chan, domainid_t pid, int *status);


/**
 * @brief requests that the process with the given PID is terminated
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to be terminated
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_kill(struct aos_rpc *chan, domainid_t pid);


/**
 * @brief requests that all processes that match the supplied name are terminated
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] name  name of the processes to be terminated
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_kill_all(struct aos_rpc *chan, const char *name);




/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H
