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
#include <barrelfish_kpi/startup_arm.h>


#include <proc_mgmt/proc_mgmt.h>

//extern void* urpc_buf;

genvaddr_t global_urpc_frames[4];

struct aos_rpc *global_rpc;
domainid_t global_pid;
struct capref global_retcap;
size_t global_retbytes;
char global_retchar;

/*
 * ===============================================================================================
 * Upcall
 * ===============================================================================================
 */

void initialize_send_handler(void *arg)
{
    debug_printf("callback to invoke the send_handler\n");
    struct aos_rpc *rpc = arg;
    errval_t err;

    err = lmp_chan_register_recv(rpc->channel, get_default_waitset(), MKCLOSURE(init_acknowledgment_handler, arg));


    // debug_printf("Checking local_cap: cnode = %u, slot = %u\n",
    //          rpc->channel->local_cap.cnode.cnode, rpc->channel->local_cap.slot);

    struct capability cap_info;
    err = invoke_cap_identify(rpc->channel->local_cap, &cap_info);
    if (err_is_fail(err)) {
        debug_printf("Invalid local_cap: %s\n", err_getstring(err));
    }

    debug_printf("rpc->channel->local->cap\n");
    debug_print_cap_at_capref(rpc->channel->local_cap);

    err = lmp_chan_send1(rpc->channel, 0, rpc->channel->local_cap, SETUP_MSG);
    if (err_is_fail(err)) {

        // Failed here
        DEBUG_ERR(err, "sending setup message");
        abort();
    }

}


/**
 * \brief Handler to process acknowledgment messages.
 *
 * This function is triggered when an acknowledgment message is received
 * from the `init` domain. It processes the message and performs necessary
 * actions based on the message content.
 *
 * \param arg Pointer to the argument passed, typically containing the RPC
 *            structure for communication.
 */
void init_acknowledgment_handler(void *arg)
{
    debug_printf("callback to invoke the init_acknowledgment_handler\n");
    struct aos_rpc *rpc = (struct aos_rpc *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref retcap;
    errval_t err;

    // Attempt to receive the message from the channel
    err = lmp_chan_recv(rpc->channel, &msg, &retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to receive acknowledgment message");
        return;
    }

    err = lmp_chan_register_recv(rpc->channel, get_default_waitset(), MKCLOSURE(init_acknowledgment_handler, arg));

    // Verify if the received message is an acknowledgment message
    if (msg.words[0] == PID_ACK) {
        //allocate a new receive slot 
        err = lmp_chan_alloc_recv_slot(rpc->channel);
        global_pid = msg.words[1];
        debug_printf("Acknowledgment received from init domain.\n");
        return;
    } else if (msg.words[0] == RAM_CAP_ACK) {
        err = lmp_chan_alloc_recv_slot(rpc->channel);
        global_retcap = retcap;
        global_retbytes = msg.words[1];
        return;
    } else if (msg.words[0] == GETCHAR_ACK) {
        err = lmp_chan_alloc_recv_slot(rpc->channel);
        global_retchar = msg.words[1];
        return;
    }

    err = lmp_chan_alloc_recv_slot(rpc->channel);
}



static void send_num_handler(void *arg)
{
    debug_printf("got into send num handler\n");
    
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
    }

    debug_printf("number sent!\n");
}

static void send_string_handler(void *arg)
{
    
    errval_t err;

    // unpack the provided string and length
    struct aos_rpc_string_payload *payload = (struct aos_rpc_string_payload *) arg;

    struct aos_rpc *rpc = payload->rpc;
    struct capref frame = payload->frame;
    size_t len = payload->len;
    struct lmp_chan *lc = rpc->channel;

    debug_printf("printing frame:\n");
    debug_print_cap_at_capref(frame);

    err = lmp_chan_send2(lc, 0, frame, STRING_MSG, len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sending string in handler\n");
        abort();
    }

    debug_printf("Sent a string successfullly\n");
}

static void send_ram_cap_req_handler(void* arg) {
    debug_printf("got into send ram cap req handler\n");
    
    errval_t err;

    struct aos_rpc_ram_cap_req_payload *payload = (struct aos_rpc_ram_cap_req_payload *) arg;

    struct aos_rpc *rpc = payload->rpc;
    struct lmp_chan *lc = rpc->channel;

    err = lmp_chan_send3(lc, 0, NULL_CAP, GET_RAM_CAP, payload->bytes, payload->alignment);
    while (err_is_fail(err)) {
        DEBUG_ERR(err, "sending ram cap req in handler\n");
        abort();
    }

    debug_printf("ram cap request sent!\n");
}

static void send_getchar_handler(void *arg)
{
    debug_printf("got into send char handler\n");
    
    errval_t err;
    struct aos_rpc *rpc = arg;
    struct lmp_chan *lc = rpc->channel;

    err = lmp_chan_send1(lc, 0, NULL_CAP, GETCHAR);
    while (err_is_fail(err)) {
        abort();
    }

    debug_printf("char sent!\n");
}

static void send_putchar_handler(void *arg) {
    debug_printf("Get into send putchar handler\n");
    
    errval_t err;
    struct aos_rpc_num_payload *payload = (struct aos_rpc_num_payload *) arg;
    struct aos_rpc *rpc = payload->rpc;
    struct lmp_chan *lc = rpc->channel;
    uintptr_t c = payload->val;

    err = lmp_chan_send2(lc, 0, NULL_CAP, PUTCHAR, c);
    while (err_is_fail(err)) {
        DEBUG_ERR(err, "sending putchar in handler\n");
        abort();
    }
}

static void send_cmdline_handler(void* arg) {
    debug_printf("got into send cmdline handler\n");
    
    errval_t err;

    // unpack the provided string and length
    struct aos_rpc_cmdline_payload *payload = (struct aos_rpc_cmdline_payload *) arg;
    struct aos_rpc *rpc = payload->rpc;
    struct capref frame = payload->frame;
    size_t len = payload->len;
    struct lmp_chan *lc = rpc->channel;

    err = lmp_chan_send3(lc, 0, frame, SPAWN_CMDLINE, len, payload->core);
    while (err_is_fail(err)) {
        DEBUG_ERR(err, "sending cmdline in handler\n");
        abort();
    }

    debug_printf("cmdline sent!\n");
}

static void send_spawn_with_caps_handler(void * arg) {
    // debug_printf("got into spawn with caps request send handler\n");
    
    errval_t err;

    // unpack the provided string and length
    struct aos_rpc_string_payload *payload = (struct aos_rpc_string_payload *) arg;
    struct aos_rpc *rpc = payload->rpc;
    struct capref frame = payload->frame;
    size_t len = payload->len;
    struct lmp_chan *lc = rpc->channel;

    err = lmp_chan_send2(lc, 0, frame, SPAWN_WITH_CAPS_MSG, len);
    while (err_is_fail(err)) {
        DEBUG_ERR(err, "sending spawn with caps request in handler\n");
        abort();
    }

    // debug_printf("spawn with caps request sent!\n");
}

/*
 * ===============================================================================================
 * Generic RPCs
 * ===============================================================================================
 */



// Get the UMP channel for communication between a specific core and the monitor
// `direction` determines the message flow:
// Used by the BSP to get the channel for a specific AP.
// direction = 0: Core-to-Monitor channel. 
// A core can notify the monitor to spawn a process, request a resource, or signal an event.

// direction = 1: Monitor-to-Core channel. 
struct ump_chan *get_channel_for_core_to_monitor(coreid_t core_id, int direction) {
    // Offset to skip bootinfo and select the correct channel
    const size_t offset = BASE_PAGE_SIZE / 2 + direction * sizeof(struct ump_chan);

    // Access the memory region assigned to the specified core for URPC
    return (struct ump_chan *)(global_urpc_frames[core_id] + offset);
}

// Get the UMP channel for communication between the current core and the monitor
// `direction` determines the message flow:
// Used by an AP to get its communication channel with the BSP.
// direction = 0: Core-to-Monitor channel.
// direction = 1: Monitor-to-Core channel.
struct ump_chan *get_channel_for_current_core(int direction) {
    //(void) direction;
    // Offset to skip bootinfo and select the correct channel
    const size_t offset = BASE_PAGE_SIZE / 2 + direction * sizeof(struct ump_chan);
    //const size_t offset = BASE_PAGE_SIZE / 2;

    // Access the shared memory region mapped for the current core and monitor
    return (struct ump_chan *)(MON_URPC_VBASE + offset);
}

// reset pointers and zero out a struct ump_chan
errval_t ump_chan_init(struct ump_chan *chan, size_t base) {
    chan->base = base;
    chan->head = 0;
    chan->tail = 0;
    chan->size = BASE_PAGE_SIZE;
    memset((void *)((genvaddr_t)chan + (genvaddr_t)chan->base), 0, BASE_PAGE_SIZE);
    return SYS_ERR_OK;
}

/**
 * @brief Sends a message to the UMP (User-level Message Passing) channel.
 * 
 * @param channel Pointer to the UMP channel structure.
 * @param message Pointer to the message buffer to send.
 * @param message_size Size of the message in bytes (maximum 60 bytes).
 * 
 * @return SYS_ERR_OK on success, or an error code on failure.
 */
errval_t ump_send(struct ump_chan *channel, char *message, size_t message_size) {
    // Check if the message size is valid
    if (message_size > 60) {
        debug_printf("Error: UMP message exceeds the maximum allowed size of 60 bytes\n");
        return LIB_ERR_UMP_BUFSIZE_INVALID;
    }

    // Check if the UMP queue has space for the new message
    if ((channel->head + 1) % BASE_PAGE_SIZE == channel->tail) {
        debug_printf("Error: UMP queue is full, cannot add new message\n");
        return LIB_ERR_UMP_CHAN_FULL;
    }

    // calculates the address of the next slot where a message will be written.
    struct cache_line *next_cache_line = 
        (struct cache_line *)((genvaddr_t)channel + channel->base + channel->head);

    // Clear to make sure there is no leftover data from previous operations.
    memset((void *)next_cache_line, 0, sizeof(struct cache_line));

    // Copy the new message into the calculated location in the circular buffer. 
    memcpy((void *)next_cache_line, message, message_size);

    // Mark the cache line as valid
    next_cache_line->valid = 1;

    // Advance the head to the next position in the circular buffer
    // Ddding sizeof(struct cache_line), the head is moved to the next slot in the buffer, where the next message will be written.
    channel->head = (channel->head + sizeof(struct cache_line)) % BASE_PAGE_SIZE;

    return SYS_ERR_OK;
}

// receive a message off the ump channel, performing the appropriate action
errval_t ump_receive(struct ump_chan *chan, void *buf) {
    // get the current cache line
    struct cache_line *cl = (struct cache_line *)((genvaddr_t)chan + chan->base + chan->tail);

    // make sure we have a message
    if (!cl->valid) {
        return LIB_ERR_NO_UMP_MSG;
    }
    
    // copy out the received message
    memcpy(buf, cl->payload, sizeof(struct ump_payload));

    // invalidate
    memset(cl, 0, sizeof(struct cache_line));

    // advance tail to next available cache line in circular buffer
    chan->tail = (chan->tail + sizeof(struct cache_line)) % BASE_PAGE_SIZE;

    debug_printf("We received something on core %d\n", disp_get_core_id());

    return SYS_ERR_OK;
}

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

    // marshall args into num payload
    struct aos_rpc_num_payload *payload = malloc(sizeof(struct aos_rpc_num_payload));
    payload->rpc = rpc;
    payload->val = num;
    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_num_handler, (void *) payload));
    
    
    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());
    
    free(payload);
    debug_printf("Sent a number successfullly\n");
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
   errval_t err;
    
    // make compiler happy about unused parameters
    (void)rpc;
    (void)string;

    struct lmp_chan *lc = rpc->channel;

    // allocate and map a frame, copying to it the string contents
    // We will actually send this frame cap
    struct capref frame;
    void *buf;
    int len = strlen(string);
    err = frame_alloc(&frame, len, NULL);
   
    err = paging_map_frame_attr(get_current_paging_state(), &buf, len, frame, VREGION_FLAGS_READ_WRITE);
    strcpy(buf, string);

    // pass the string frame and length in the payload
    struct aos_rpc_string_payload *payload = malloc(sizeof(struct aos_rpc_string_payload));

    payload->rpc = rpc;
  
    payload->frame = frame;
   
    payload->len = len;

    
    err = lmp_chan_alloc_recv_slot(lc);
   
   // send the frame and the length on the channel
    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_string_handler, (void *)payload));
    
    event_dispatch(get_default_waitset());
    //debug_printf("between two dispatch\n");
    event_dispatch(get_default_waitset());
   //debug_printf("after two dispatch\n");

    free(payload);

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

    struct lmp_chan *lc = rpc->channel;
    errval_t err;
    
    struct aos_rpc_ram_cap_req_payload payload;
    payload.rpc = rpc;
    payload.bytes = bytes;
    payload.alignment = alignment;

    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_ram_cap_req_handler, 
                                 (void *) &payload));
    
    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());

    if (capref_is_null(global_retcap)) {
        debug_printf("downloading ram failed\n");
        return LIB_ERR_RAM_ALLOC;
    }

    *ret_cap = global_retcap;
    *ret_bytes = global_retbytes;
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
    struct lmp_chan *lc = rpc->channel;
    errval_t err;

    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_getchar_handler, (void *) rpc));
    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());
    *retc = global_retchar;

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
    // TODO: implement functionality to send a number over the channel
    // given channel and wait until the ack gets returned.

    struct lmp_chan *lc = rpc->channel;
    errval_t err;
    

    struct aos_rpc_num_payload payload;
    payload.rpc = rpc;
    payload.val = c;
    
    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_putchar_handler, (void *)&payload));


    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());

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
errval_t aos_rpc_proc_spawn_with_caps(struct aos_rpc *rpc, int argc, const char *argv[], int capc,
                                      struct capref cap, coreid_t core, domainid_t *newpid)
{
    errval_t err;
    debug_printf("Got in the aos_rpc_proc_spawn_with_cap function \n");

    // Log all arguments for debugging
    for (int i = 0; i < argc; i++) {
        debug_printf("arg %d: %s\n", i, argv[i]);
    }

    // Step 1: Allocate a frame to hold arguments
    struct capref frame;
    err = frame_alloc(&frame, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate frame for arguments");
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // Step 2: Map the allocated frame into virtual memory
    void *buf;
    err = paging_map_frame_attr(get_current_paging_state(), &buf, BASE_PAGE_SIZE, frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to map frame");
    }

    // Step 3: Prepare the input structure within the allocated frame
    struct spawn_with_caps_frame_input *input = (struct spawn_with_caps_frame_input *)buf;
    input->argc = argc;
    for (int i = 0; i < argc; i++) {
        strcpy(input->argv[i], argv[i]);  // Copy each argument to the input frame
    }
    input->capc = capc;
    input->cap = cap;
    input->core = core;

    // Step 4: Allocate a receive slot on the LMP channel
    struct lmp_chan *lc = rpc->channel;
    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate receive slot on LMP channel");
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    // Step 5: Send the frame capability and length via the LMP channel
    struct aos_rpc_string_payload *payload = malloc(sizeof(struct aos_rpc_string_payload));
    if (!payload) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "Failed to allocate memory for string payload");
        return LIB_ERR_MALLOC_FAIL;
    }

    payload->rpc = rpc;
    payload->frame = frame;
    payload->len = BASE_PAGE_SIZE;

    // Register the send handler and dispatch the event
    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_spawn_with_caps_handler, (void *)payload));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register send handler");
        free(payload);
    }

    // Dispatch the waitset to process the event
    err = event_dispatch(get_default_waitset());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Event dispatch failed");
        free(payload);
        return err_push(err, LIB_ERR_EVENT_DISPATCH);
    }

    // Step 6: Retrieve the PID of the spawned process
    *newpid = input->pid;
    debug_printf("PID of the new process: %d\n", input->pid);

    // Free the allocated payload
    free(payload);

    return SYS_ERR_OK;
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

    errval_t err;

    debug_printf("Got in the RPC for spawn cmdline\n");
    debug_printf("Here's the cmdline: %s\n", cmdline);
    struct lmp_chan *lc = chan->channel;

    // allocate and map a frame, copying to it the string contents
    struct capref frame;
    void *buf;
    int len = strlen(cmdline);
  

    err = frame_alloc(&frame, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("could not allocate frame\n");
    }    

    err = paging_map_frame_attr(get_current_paging_state(), &buf, BASE_PAGE_SIZE, frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        debug_printf("could not map frame\n");
    }    


    strcpy(buf, cmdline);

    // pass the string frame and length in the payload
    struct aos_rpc_cmdline_payload *payload = malloc(sizeof(struct aos_rpc_cmdline_payload));
    payload->rpc = chan;
    payload->frame = frame;
    payload->len = len;
    payload->core = core;
    debug_printf("here is the initial value of pid: %d\n", global_pid);

    // send the frame and the length on the channel
    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        debug_printf("could not lmp_chan_alloc_recv_slot\n");
    }


    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_cmdline_handler, (void *)payload));
    if (err_is_fail(err)) {
        debug_printf("could not lmp_chan_register_send\n");
    }

    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());
  
    *newpid = global_pid;

    free(payload);
    
    return SYS_ERR_OK;
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

    struct lmp_chan *lc = chan->channel;
    errval_t err;

    struct capref frame;
    void *buf;
    err = frame_alloc(&frame, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        USER_PANIC("fram alloc failed\n");
    }
    err = paging_map_frame_attr(get_current_paging_state(), &buf, BASE_PAGE_SIZE, frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        USER_PANIC("map frame failed\n");
    }
    *((int *) buf) = status;
    ((int *) buf)[1] = disp_get_domain_id();

    // wrap the payload for handler 
    struct aos_rpc_string_payload *payload = malloc(sizeof(struct aos_rpc_string_payload));
    payload->rpc = chan;
    payload->frame = frame;
    payload->len = BASE_PAGE_SIZE;

    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        USER_PANIC("map frame failed\n");
    }

    //send pid and exit msg
    err = lmp_chan_register_send(lc, get_default_waitset(), MKCLOSURE(send_exit_handler, (void *)payload));
    if (err_is_fail(err)) {
        USER_PANIC("map frame failed\n");
    }
    event_dispatch(get_default_waitset());
    event_dispatch(get_default_waitset());


    free(payload);

    //err = aos_rpc_proc_kill(chan, disp_get_domain_id()); Processor manager halt the excecution

    return SYS_ERR_OK;

    // TODO: implement the process exit RPC
    // DEBUG_ERR(LIB_ERR_NOT_IMPLEMENTED, "%s not implemented", __FUNCTION__);
    // return LIB_ERR_NOT_IMPLEMENTED;
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
    debug_printf("Entering aos_rpc_init function\n");

    // Allocate memory for the LMP channel
    rpc->channel = malloc(sizeof(struct lmp_chan));
    if (rpc->channel == NULL) {
        debug_printf("Failed to allocate memory for LMP channel\n");
        return LIB_ERR_MALLOC_FAIL;
    }
    debug_printf("Successfully allocated memory for LMP channel\n");

    // Initialize the LMP channel
    debug_printf("Initializing the LMP channel\n");
    lmp_chan_init(rpc->channel);
    debug_printf("LMP channel initialized successfully\n");

    debug_printf("Exiting aos_rpc_init function\n");
    return SYS_ERR_OK;
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    debug_printf("Entering aos_rpc_get_init_channel...\n");
    errval_t err;
    struct aos_rpc *rpc = global_rpc;

    if (global_rpc == NULL) {
        debug_printf("Global RPC is NULL. Allocating a new aos_rpc structure...\n");

        // Allocate memory for the RPC structure
        rpc = malloc(sizeof(struct aos_rpc));
        if (rpc == NULL) {
            debug_printf("Failed to allocate memory for aos_rpc structure.\n");
            return NULL;
        }
        debug_printf("Allocated memory for aos_rpc at address: %p\n", (void *)rpc);

        // Initialize the RPC structure
        err = aos_rpc_init(rpc);
        if (err_is_fail(err)) {
            debug_printf("Failed to initialize aos_rpc: %s\n", err_getstring(err));
            free(rpc);  // Clean up allocated memory on failure
            return NULL;
        }
        debug_printf("Successfully initialized aos_rpc.\n");

        // Accept the LMP channel
        debug_printf("Attempting to accept the LMP channel...\n");
  

        err = lmp_chan_accept(rpc->channel, DEFAULT_LMP_BUF_WORDS, cap_initep);
        if (err_is_fail(err)) {
            debug_printf("Failed to accept LMP channel: %s\n", err_getstring(err));
            free(rpc);  // Clean up allocated memory on failure
            return NULL;
        }
        debug_printf("Successfully accepted the LMP channel.\n");
    } else {
        debug_printf("Global RPC already initialized. Reusing existing aos_rpc structure at address: %p\n", (void *)global_rpc);
    }

    // Update global RPC pointer
    global_rpc = rpc;

    debug_printf("Exiting aos_rpc_get_init_channel with aos_rpc at address: %p\n", (void *)rpc);
    return rpc;
}


/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    // TODO: Return channel to talk to memory server process (or whoever
    // implements memory server functionality)
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    // TODO: Return channel to talk to process server process (or whoever
    // implements process server functionality)
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    return aos_rpc_get_init_channel();
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
    }
}



void send_exit_handler(void * arg) {
    //debug_printf("get into send exit handler\n");
    
    errval_t err;

    struct aos_rpc_string_payload *payload = (struct aos_rpc_string_payload *) arg;
    struct aos_rpc *rpc = payload->rpc;
    struct capref frame = payload->frame;
    size_t len = payload->len;
    struct lmp_chan *lc = rpc->channel;



    err = lmp_chan_send2(lc, 0, frame, EXIT_MSG, len);
    if (err_is_fail(err)) {
        USER_PANIC("sending exit message fialed:%s\n", err_getstring(err));
    }

    //debug_printf("Sent exit msg\n");
}



// Register the receive handler
void setup_receive_handler(struct aos_rpc *rpc)
{
    lmp_chan_register_recv(rpc->channel, rpc->ws, MKCLOSURE(receive_number_handler, rpc));
}
