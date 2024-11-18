/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading/grading.h>
#include <grading/io.h>

#include "mem_alloc.h"
#include "coreboot.h"


struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;
void send_ack_handler(void *arg);


int main_loop(struct waitset *ws);

 int main_loop(struct waitset *ws)
 {
    // go into messaging main loop
    while (true) {
        errval_t err = event_dispatch(ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in main event_dispatch loop");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
 }

void send_ack_handler(void *arg)
{
    debug_printf("sending ack\n");
    struct aos_rpc *rpc = arg;
    struct lmp_chan *chan = rpc->channel;
    errval_t err;
    err = lmp_chan_send1(chan, 0, NULL_CAP, ACK_MSG);
    while (err_is_fail(err)) {
        debug_printf("\n\n\n\n went into our error while loop\n\n\n\n");
    }

    debug_printf("ack sent\n");
}

void gen_recv_handler(void *arg) {
    debug_printf("Enter the general recv handler!!!!\n");
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct aos_rpc *rpc = arg;
    errval_t err;
    
    struct capref remote_cap;
    slot_alloc(&remote_cap);
    err = lmp_chan_recv(rpc->channel, &msg, &remote_cap);
    
    // reregister receive handler
    err = lmp_chan_register_recv(rpc->channel, get_default_waitset(), MKCLOSURE((void *) gen_recv_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, err_getstring(err));
        return;
    }
        
    debug_printf("msg words[0]: %d\n", msg.words[0]);
    switch(msg.words[0]) {
        case SETUP_MSG:
            // is cap setup message
            debug_printf("it is in the Set up meg\n");
            rpc->channel->remote_cap = remote_cap;
            while (err_is_fail(err)) {
                debug_printf("\n\n\nlooks like the code ran\n\n\n");

            }

            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE((void *) send_ack_handler, (void *) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }
            event_dispatch(get_default_waitset());
            break;

        case NUM_MSG:
            // is num
            debug_printf("Hey, I know the message is Nnumber now!!\n");
            while (err_is_fail(err)) {
                debug_printf("\n\n\nlooks like the code ran\n\n\n");
            }
            grading_rpc_handle_number(msg.words[1]);

            debug_printf("here is the number we recieved: %d\n", msg.words[1]);

            event_dispatch(get_default_waitset());
            break;
        case STRING_MSG:
            debug_printf("is string\n");
            while (err_is_fail(err)) {
                debug_printf("\n\n\nlooks like the code ran\n\n\n");
            }

            debug_printf("here is the length we recieved: %d\n", msg.words[1]);
            debug_print_cap_at_capref(remote_cap);
            void *buf;
            err = paging_map_frame_attr(get_current_paging_state(), &buf, msg.words[1], remote_cap, VREGION_FLAGS_READ_WRITE);

            // debug_printf("here is the string we recieved: %s\n", buf);
            grading_rpc_handler_string(buf);

            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_ack_handler, (void*) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }
            break;
        
        default:
            debug_printf("received unknown message type\n");
            abort();
    }

    debug_printf("out the switch!\n");

    // allocate a new slot
    // TODO: allocate only when needed
    err = lmp_chan_alloc_recv_slot(rpc->channel);
}

static int
bsp_main(int argc, char *argv[]) {
    errval_t err;

    // initialize the grading/testing subsystem
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*)strtol(argv[1], NULL, 10);
    assert(bi);

    // initialize our RAM allocator
    err = initialize_ram_alloc(bi);
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "initialize_ram_alloc");
    }

    // TODO: initialize mem allocator, vspace management here

    // calling early grading tests, required functionality up to here:
    //   - allocate memory
    //   - create mappings in the address space
    //   - spawn new processes
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_test_early();


    switch (platform_info.platform) {
        case PI_PLATFORM_IMX8X: {
            // SPAWN THE SECOND CORE on the IMX8X baord
            hwid_t mpid = 1;
            err = coreboot_boot_core(mpid, "boot_armv8_generic", "cpu_imx8x", "init", NULL);
            break;
        }
        case PI_PLATFORM_QEMU: {
            // SPAWN THE SECOND CORE on QEMU
            hwid_t mpid = 1;
            err = coreboot_boot_core(mpid, "boot_armv8_generic", "cpu_a57_qemu", "init", NULL);
            break;
        }
        default:
            debug_printf("Unsupported platform\n");
            return LIB_ERR_NOT_IMPLEMENTED;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Booting second core failed. Continuing.\n");
    }

    // TODO: Spawn system processes, boot second core etc. here

    // calling late grading tests, required functionality up to here:
    //   - full functionality of the system
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_test_late();

    debug_printf("Message handler loop\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    
    return main_loop(get_default_waitset());

    return EXIT_SUCCESS;
}

static int
app_main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    errval_t err;
    // TODO (M5):
    //   - initialize memory allocator etc.
    //   - obtain a pointer to the bootinfo structure on the appcore!

    // initialize the grading/testing subsystem
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_setup_app_init(bi);

    // calling early grading tests, required functionality up to here:
    //   - allocate memory
    //   - create mappings in the address space
    //   - spawn new processes
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_test_early();

    // TODO (M7)
    //  - initialize subsystems for nameservice, distops, ...

    // TODO(M5): signal the other core that we're up and running

    // TODO (M6): initialize URPC

    // calling late grading tests, required functionality up to here:
    //   - full functionality of the system
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_test_late();

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    errval_t err;

    /* obtain the core information from the kernel*/
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the core id from the kernel\n");
    }

    /* Set the core id in the disp_priv struct */
    disp_set_core_id(my_core_id);

    /* obtain the platform information */
    err = invoke_kernel_get_platform_info(cap_kernel, &platform_info);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the platform info from the kernel\n");
    }

    char *platform;
    switch (platform_info.platform) {
        case PI_PLATFORM_QEMU:
            platform = "QEMU";
            break;
        case PI_PLATFORM_IMX8X:
            platform = "IMX8X";
            break;
        default:
            platform = "UNKNOWN";
    }

    err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    // this print statement shoudl remain here
    grading_printf("init domain starting on core %" PRIuCOREID " (%s)", my_core_id, platform);
    fflush(stdout);

    if(my_core_id == 0) return bsp_main(argc, argv);
    else                return app_main(argc, argv);
}
