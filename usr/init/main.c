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

    // this print statement shoudl remain here
    grading_printf("init domain starting on core %" PRIuCOREID " (%s)", my_core_id, platform);
    fflush(stdout);

    if(my_core_id == 0) return bsp_main(argc, argv);
    else                return app_main(argc, argv);
}
