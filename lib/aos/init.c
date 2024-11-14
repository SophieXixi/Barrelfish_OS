/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/aos_rpc.h>


#include "threads_priv.h"
#include "init.h"

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    debug_printf("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {}
}

static void libc_assert(const char *expression, const char *file,
                        const char *function, int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf), "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN,
                   disp_name(), expression, function, file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__))
static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if(len) {
        errval_t err = sys_print(buf, len);
        if (err_is_fail(err)) {
            return 0;
        }
    }
    return len;
}

__attribute__((__used__))
static size_t dummy_terminal_read(char *buf, size_t len)
{
    (void)buf;
    (void)len;
    debug_printf("Terminal read NYI!\n");
    return 0;
}

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = dummy_terminal_read;
    _libc_terminal_write_func = syscall_terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}


void initialize_send_handler(void *arg)
{
    debug_printf("callback to invoke the send_handler\n");
    struct aos_rpc *rpc = arg;
    errval_t err;

    err = lmp_chan_register_recv(rpc->channel, get_default_waitset(), MKCLOSURE(init_acknowledgment_handler, arg));

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
    struct capref cap;
    errval_t err;

    // Attempt to receive the message from the channel
    err = lmp_chan_recv(rpc->channel, &msg, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to receive acknowledgment message");
        return;
    }

     err = lmp_chan_register_recv(rpc->channel, get_default_waitset(), MKCLOSURE(init_acknowledgment_handler, arg));

    // Verify if the received message is an acknowledgment message
    if (msg.words[0] == PID_ACK) {
        //allocate a new receive slot 
        err = lmp_chan_alloc_recv_slot(rpc->channel);
        debug_printf("Acknowledgment received from init domain.\n");
    } else {
        debug_printf("Unexpected message type received in acknowledgment handler.\n");
    }
}


/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // initialize the slot allocator first, ram alloc will require this
    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = ram_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_INIT);
    }

    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }



    lmp_endpoint_init();

    // HINT: Use init_domain to check if we are the init domain.
    if (init_domain) {
        err = cap_retype(cap_selfep,cap_dispatcher,0,ObjType_EndPointLMP,0);
        debug_printf("This is the init domain\n");
    }

    // TODO MILESTONE 4: register ourselves with init

    // Obtain a reference to the init RPC channel
    struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
    struct lmp_chan *init_rpc_channel = init_rpc->channel;

    /* allocate lmp channel structure */
    /* create local endpoint */
    struct capref local_ep_cap;
    err = endpoint_create(64, &local_ep_cap, &init_rpc_channel->endpoint);
    if (err_is_fail(err)) {
        free(init_rpc_channel);
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }
    /* set remote endpoint to init's endpoint */
    /* set receive handler */
    err = lmp_chan_alloc_recv_slot(init_rpc->channel);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }
    /* send local ep to init */
     err = lmp_chan_register_send(init_rpc->channel, get_default_waitset(), MKCLOSURE(initialize_send_handler, (void *) init_rpc));
    /* wait for init to acknowledge receiving the endpoint */
    /* initialize init RPC client with lmp channel */


    /* TODO MILESTONE 4: now we should have a channel with init set up and can
     * use it for the ram allocator */


    /* set init RPC client in our program state */
    set_init_rpc(init_rpc);

    
    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here
    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
