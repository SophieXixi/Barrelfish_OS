/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>



genvaddr_t global_urpc_frames[4];

struct aos_rpc *global_rpc;


/*
 * ===============================================================================================
 * Generic RPCs
 * ===============================================================================================
 */

/**
 * @brief Send a single number over an RPC channel.
 *
 * @param[in] chan  the RPC channel to use
 * @param[in] val   the number to send
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 *
 * Channel: init
 */
errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    struct lmp_chan *lc = rpc->channel;
    errval_t err;

    // Create a buffer for the message
    err = lmp_chan_send1(lc, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, num);
    if (err_is_fail(err)) {
        debug_printf("Failed to send number: %s\n", err_getstring(err));
        return err;
    }

    debug_printf("Number %lu sent successfully over RPC channel.\n", num);

    // Wait for acknowledgment
    rpc->waiting_for_reply = true;
    while (rpc->waiting_for_reply) {
        err = event_dispatch(rpc->ws);
        if (err_is_fail(err)) {
            debug_printf("Error in event dispatch while waiting for reply: %s\n", err_getstring(err));
            return err;
        }
    }

    debug_printf("Acknowledgment received for number %lu.\n", num);

    return SYS_ERR_OK;
}


/**
 * @brief Send a single number over an RPC channel.
 *
 * @param[in] chan  the RPC channel to use
 * @param[in] val   the string to send
 *
 * @returns SYS_ERR_OK on success, or error value on failure
 *
 * Channel: init
 */
errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    // make compiler happy about unused parameters
    (void)rpc;
    (void)string;

    // TODO: implement functionality to send a string over the given channel
    // and wait for a response.
    return SYS_ERR_OK;
}


/*
 * ===============================================================================================
 * RAM Alloc RPCs
 * ===============================================================================================
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
errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // make compiler happy about unused parameters
    (void)rpc;
    (void)bytes;
    (void)alignment;
    (void)ret_cap;
    (void)ret_bytes;

    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.
    // Hint: think about where the received cap will be stored
    return SYS_ERR_OK;
}



/*
 * ===============================================================================================
 * Serial RPCs
 * ===============================================================================================
 */


/**
 * @brief obtains a single character from the serial
 *
 * @param chan  the RPC channel to use (serial channel)
 * @param retc  returns the read character
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // make compiler happy about unused parameters
    (void)rpc;
    (void)retc;

    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}



/**
 * @brief sends a single character to the serial
 *
 * @param chan  the RPC channel to use (serial channel)
 * @param c     the character to send
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // make compiler happy about unused parameters
    (void)rpc;
    (void)c;

    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}


/*
 * ===============================================================================================
 * Processes RPCs
 * ===============================================================================================
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
                                      struct capref cap, coreid_t core, domainid_t *newpid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)argc;
    (void)argv;
    (void)capc;
    (void)cap;
    (void)core;
    (void)newpid;

    // TODO: implement the process spawn with caps RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}



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
                                         domainid_t *newpid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)cmdline;
    (void)core;
    (void)newpid;

    // TODO: implement the process spawn with cmdline RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


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
                                              domainid_t *newpid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)path;
    (void)core;
    (void)newpid;

    // TODO: implement the process spawn with default args RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief obtains a list of PIDs of all processes in the system
 *
 * @param[in]  chan       the RPC channel to use (process channel)
 * @param[out] pids       array of PIDs of all processes in the system (freed by caller)
 * @param[out] pid_count  the number of PIDs in the list
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_get_all_pids(struct aos_rpc *chan, domainid_t **pids, size_t *pid_count)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pids;
    (void)pid_count;

    // TODO: implement the process get all PIDs RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}

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
                                 char *cmdline, int cmdline_max, uint8_t *state, int *exit_code)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;
    (void)core;
    (void)cmdline;
    (void)cmdline_max;
    (void)state;
    (void)exit_code;

    // TODO: implement the process get status RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief obtains the name of a process with a given PID
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] name  the name of the process to search for
 * @param[in] pid   returns PID of the process to pause/suspend
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_get_name(struct aos_rpc *chan, domainid_t pid, char *name, size_t len)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;
    (void)name;
    (void)len;

    // TODO: implement the process get name RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


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
errval_t aos_rpc_proc_get_pid(struct aos_rpc *chan, const char *name, domainid_t *pid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)name;
    (void)pid;

    // TODO: implement the process get PID RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief pauses or suspends the execution of a running process
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to pause/suspend
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_pause(struct aos_rpc *chan, domainid_t pid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;

    // TODO: implement the process pause RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief resumes a previously paused process
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to resume
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_resume(struct aos_rpc *chan, domainid_t pid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;

    // TODO: implement the process resume RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


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
errval_t aos_rpc_proc_exit(struct aos_rpc *chan, int status)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)status;

    // TODO: implement the process exit RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


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
errval_t aos_rpc_proc_wait(struct aos_rpc *chan, domainid_t pid, int *status)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;
    (void)status;

    // TODO: implement the process wait RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief requests that the process with the given PID is terminated
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] pid   PID of the process to be terminated
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_kill(struct aos_rpc *chan, domainid_t pid)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)pid;

    // TODO: implement the process kill RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief requests that all processes that match the supplied name are terminated
 *
 * @param[in] chan  the RPC channel to use (process channel)
 * @param[in] name  name of the processes to be terminated
 *
 * @return SYS_ERR_OK on success, or error value on failure
 */
errval_t aos_rpc_proc_kill_all(struct aos_rpc *chan, const char *name)
{
    // make compiler happy about unused parameters
    (void)chan;
    (void)name;

    // TODO: implement the process killall RPC
    DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t aos_rpc_init(struct aos_rpc *rpc) {
    errval_t err;

    // Initialize the LMP channel within the RPC structure
    rpc->channel = malloc(sizeof(struct lmp_chan));

    lmp_chan_init(rpc->channel);
    debug_printf("Initialized LMP channel\n");

    // Step 1: Set up the local endpoint for receiving messages
    struct capref local_ep;
    err = slot_alloc(&local_ep);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    // Retype the dispatcher capability to an endpoint and mint it
    struct capref dispatcher_cap = cap_dispatcher;  // The parent’s dispatcher capability
    err = cap_retype(local_ep, dispatcher_cap, 0, ObjType_EndPointLMP, LMP_RECV_LENGTH);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    // Mint the endpoint with a buffer for message storage
    struct capref final_ep;
    err = slot_alloc(&final_ep);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = cap_mint(final_ep, local_ep, LMP_RECV_LENGTH, LMP_RECV_LENGTH);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_MINT);
    }

    // Assign the local endpoint to the LMP channel's `local_cap` for receiving messages
    rpc->channel->local_cap = final_ep;

    // Step 2: Set up the channel for accepting messages
    err = lmp_chan_accept(rpc->channel, DEFAULT_LMP_BUF_WORDS, rpc->channel->local_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
    }

    // Step 3: Set the remote endpoint for sending messages
    // After spawning the child, the child’s endpoint should be copied to a known slot
    struct capref remote_ep = {
        .cnode = cnode_task,  // Adjust to parent’s view of child endpoint slot
        .slot = TASKCN_SLOT_SELFEP
    };
    rpc->channel->remote_cap = remote_ep;
    printf("Remote endpoint capability set:\n");
    printf("  cnode.croot = %u, cnode.cnode = %u, cnode.level = %u\n", 
           remote_ep.cnode.croot, remote_ep.cnode.cnode, remote_ep.cnode.level);
    printf("  slot = %u\n", remote_ep.slot);


    debug_printf("aos_rpc_init completed: local and remote endpoints set up\n");
    return SYS_ERR_OK;
}



/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    errval_t        err;
    struct aos_rpc *rpc = global_rpc;
    // debug_printf("entered init channel\n");

    if (global_rpc == NULL) {
        // debug_printf("creating new aos_rpc channel\n");
        rpc = malloc(sizeof(struct aos_rpc));
        printf("malloced rpc\n");
        if (rpc == NULL) {
            // debug_printf("aos_rpc_get_init_channel: malloc failed\n");
            return NULL;
        }
        aos_rpc_init(rpc);

        err = lmp_chan_accept(rpc->channel, DEFAULT_LMP_BUF_WORDS, cap_initep);
        printf("accepted lmp\n");

    }

    global_rpc = rpc;
    return rpc;
}
/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    // TODO: Return channel to talk to memory server process (or whoever
    // implements memory server functionality)
    debug_printf("aos_rpc_get_memory_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    // TODO: Return channel to talk to process server process (or whoever
    // implements process server functionality)
    debug_printf("aos_rpc_get_process_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    debug_printf("aos_rpc_get_serial_channel NYI\n");
    return NULL;
}





// Receive handler for a number
void receive_number_handler(void *arg)
{
errval_t err;
    struct aos_rpc_num_payload *payload = (struct aos_rpc_num_payload *) arg;
    struct aos_rpc *rpc = payload->rpc;
    struct lmp_chan *lc = rpc->channel;
    uintptr_t num = payload->val;


    err = lmp_chan_send2(lc, 0, NULL_CAP, NUM_MSG, num);
    while (lmp_err_is_transient(err)) {
        err = lmp_chan_send2(lc, 0, NULL_CAP, NUM_MSG, num);
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sending num in handler\n");
        abort();
    }}

// Register the receive handler
void setup_receive_handler(struct aos_rpc *rpc)
{
    lmp_chan_register_recv(rpc->channel, rpc->ws, MKCLOSURE(receive_number_handler, rpc));
}
