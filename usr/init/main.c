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
#include <aos/kernel_cap_invocations.h>
#include <mm/mm.h>
#include <grading/grading.h>
#include <grading/io.h>
#include <spawn/spawn.h>
#include <spawn/multiboot.h>

#include "coreboot.h"
#include "mem_alloc.h"
#include "proc_mgmt.h"

#include <barrelfish_kpi/startup_arm.h>

#include <drivers/lpuart.h>
#include <drivers/pl011.h>
#include <drivers/gic_dist.h>
#include <maps/qemu_map.h>
#include <maps/imx8x_map.h>
#include <aos/inthandler.h>
#include <barrelfish_kpi/startup_arm.h>
#include <proc_mgmt/proc_mgmt.h>
#include <aos/caddr.h>

bool qemu;
struct pl011_s *pl011;
struct lpuart_s *lpuart;

extern struct process_manager *proc_manager;
extern void initialize_process_manager(struct process_manager **pm);
extern void *urpc_buf;

//void* urpc_buf;

struct bootinfo *bi;
coreid_t my_core_id;

int num_mod_names;
char mod_names[MOD_NAME_MAX_NUM][MOD_NAME_LEN];


struct platform_info platform_info;
void send_ack_handler(void *arg);
void send_char_handler(void *arg);
void send_ramCp_handler(void *arg);
void send_pid_handler(void *arg);

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
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed in the send ack handler\n");
        return;
    }

    debug_printf("ack sent\n");
}


void send_char_handler(void *arg)
{
    debug_printf("sending char\n");
    struct aos_rpc_num_payload *payload = arg;
    struct aos_rpc *rpc = payload->rpc;
    struct lmp_chan *chan = rpc->channel;
    char c = payload->val;
    errval_t err;
    err = lmp_chan_send2(chan, 0, NULL_CAP, GETCHAR_ACK, c);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed sending char\n");
    }

    free(payload);

    debug_printf("char sent: %c\n", c);
}


void send_ramCp_handler(void *arg) 
{
    debug_printf("sending ram cap response\n");
    struct aos_rpc_ram_cap_resp_payload* resp = arg;
    struct lmp_chan *chan = resp->rpc->channel;

    debug_printf("sent ram cap size: %d\n", resp->ret_bytes);
    errval_t err = lmp_chan_send2(chan, 0, resp->ret_cap, RAM_CAP_ACK, resp->ret_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed in the Send Ram CAP handler\n");
        return;
    }

    free(resp);

    debug_printf("ram cap resp sent\n");
}

void send_pid_handler(void *arg) {
    debug_printf("sending our pid handler\n");
    struct aos_rpc_cmdline_payload *payload = arg;
    struct aos_rpc *rpc = payload->rpc;
    struct lmp_chan *chan = rpc->channel;
    errval_t err;
    err = lmp_chan_send2(chan, 0, NULL_CAP, PID_ACK, payload->pid);

    free(payload);

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
            debug_printf("This is Setup case in the gen_recv_handler\n");
            rpc->channel->remote_cap = remote_cap;

            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE((void *) send_ack_handler, (void *) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }

            event_dispatch(get_default_waitset());
            break;

        case NUM_MSG:
            // is num
            debug_printf("This is Number message case in the gen_recv_handler\n");
    
            grading_rpc_handle_number(msg.words[1]);

            debug_printf("here is the number we recieved: %d\n", msg.words[1]);
            
            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_ack_handler, (void*) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }

            event_dispatch(get_default_waitset());
            event_dispatch(get_default_waitset());

            break;
        case STRING_MSG:
            debug_printf("This is String MSG in the gen_recv_handler\n");

            debug_printf("here is the length we recieved: %d\n", msg.words[1]);
            debug_print_cap_at_capref(remote_cap);
            void *buf;
            err = paging_map_frame_attr(get_current_paging_state(), &buf, msg.words[1], remote_cap, VREGION_FLAGS_READ_WRITE);

            debug_printf("here is the string we recieved: %s\n", buf);
            grading_rpc_handler_string(buf);

            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_ack_handler, (void*) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }
            break;
        case GET_RAM_CAP:
            debug_printf("This is RAM CAP case in the gen_recv_handler\n");

            // Step 1: Allocate memory for the response structure
            struct aos_rpc_ram_cap_resp_payload *ramResponse = malloc(sizeof(struct aos_rpc_ram_cap_resp_payload));
            if (ramResponse == NULL) {
                debug_printf("Error: Failed to allocate memory for RAM response payload\n");
                return;
            }
            debug_printf("Successfully allocated memory for RAM response payload\n");

            ramResponse->rpc = rpc;
            ramResponse->ret_cap = NULL_CAP;
            ramResponse->ret_bytes = 0;

            // Step 2: Locate the requesting process using process manager
            debug_printf("Checking memory allocation limits for PID: %d\n", rpc->pid);

            // struct proc_status process_status;
            // err = proc_mgmt_get_status(rpc->pid, &process_status);
            // if (err_is_fail(err)) {
            //     debug_printf("Error: Could not find process with PID: %d\n", rpc->pid);
            //     free(ramResponse);
            //     return;
            // }

            if (proc_manager == NULL) {
                debug_printf("Error: Process manager is not initialized\n");
                return;
            }
            debug_printf("Process manager initialized successfully\n");

            // Get allocated pages and memory limits
            struct process_node *proc_node = proc_manager->head;
            
            // while (proc_node != NULL && proc_node->si->pid != rpc->pid) {
            //     proc_node = proc_node->next;
            // }

            // if (proc_node == NULL) {
            //     debug_printf("Error: Process node not found for PID: %d\n", rpc->pid);
            //     free(ramResponse);
            //     return;
            // }

            debug_printf("Current allocated pages: %d, Requested pages: %d, Max allowed pages: %d\n",
                        proc_node->si->pages_allocated,
                        ROUND_UP(msg.words[1], BASE_PAGE_SIZE) / BASE_PAGE_SIZE,
                        MAX_PROC_PAGES);

            // Step 3: Check memory limit
            if (proc_node->si->pages_allocated + ROUND_UP(msg.words[1], BASE_PAGE_SIZE) / BASE_PAGE_SIZE <= MAX_PROC_PAGES) {
                debug_printf("Memory allocation request is within limits. Proceeding to allocate RAM.\n");

                err = ram_alloc_aligned(&ramResponse->ret_cap, msg.words[1], msg.words[2]);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "Failed to allocate RAM for process\n");
                    free(ramResponse);
                    return;
                }
                ramResponse->ret_bytes = ROUND_UP(msg.words[1], BASE_PAGE_SIZE);

                // Update process allocated pages
                proc_node->si->pages_allocated += ROUND_UP(msg.words[1], BASE_PAGE_SIZE) / BASE_PAGE_SIZE;

                debug_printf("Successfully allocated RAM. Capability: ");
                debug_print_cap_at_capref(ramResponse->ret_cap);
                debug_printf("Allocated bytes: %zu\n", ramResponse->ret_bytes);

                grading_rpc_handler_ram_cap(ramResponse->ret_bytes, msg.words[2]);
            } else {
                debug_printf("Memory allocation request exceeds limits. No RAM allocated.\n");
            }

            // Step 4: Register send handler
            debug_printf("Registering send handler to respond to the RAM request\n");
            err = lmp_chan_register_send(rpc->channel, get_default_waitset(),
                                        MKCLOSURE(send_ramCp_handler, (void *)ramResponse));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to register send handler\n");
                free(ramResponse);
                return;
            }
            debug_printf("Done in the RAM CAP case in Recv handler\n");

            break;

        case PUTCHAR:
            debug_printf("This is Put char case in the gen_recv_handler\n");
            
            grading_rpc_handler_serial_putchar(msg.words[1]);
            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_ack_handler, (void*) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, err_getstring(err));
                return;
            }
            break;
            
         case GETCHAR:
            debug_printf("This is Get char case in the gen_recv_handler\n");
            while (err_is_fail(err)) {
                USER_PANIC_ERR(err, "registering receive handler\n");
            }

            char c = 'A';
          
            grading_rpc_handler_serial_getchar();

            // build getchar response message payload
            struct aos_rpc_num_payload *num_payload = malloc(sizeof(struct aos_rpc_num_payload));
            num_payload->rpc = rpc;
            num_payload->val = c;

            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_char_handler, (void*) num_payload));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, err_getstring(err));
                return;
            }

            event_dispatch(get_default_waitset());
            event_dispatch(get_default_waitset());

            break;
         case SPAWN_CMDLINE:
            debug_printf("This is SPAWN_CMDLINE case in the gen_recv_handler\n");
          
            struct aos_rpc_cmdline_payload *payload = malloc(sizeof(struct aos_rpc_cmdline_payload));
            
            debug_printf("Here is the length we recieved: %d\n", msg.words[1]);
            void *buf2;
            err = paging_map_frame_attr(get_current_paging_state(), &buf2, msg.words[1], remote_cap, VREGION_FLAGS_READ_WRITE);

            domainid_t our_pid;
            err = proc_mgmt_spawn_with_cmdline(buf2, msg.words[2], &our_pid);
            if (err_is_fail(err)) {
                debug_printf("spawn failed\n");
            }

            payload->pid = our_pid;
            payload->rpc = rpc;
            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_pid_handler, (void*) payload));
            grading_rpc_handler_process_spawn(buf2, msg.words[2]);

            break;
        case EXIT_MSG:
            debug_printf("This is EXIT_MSG case in the gen_recv_handler\n");

            void *buf3;
            err = paging_map_frame_attr(get_current_paging_state(), &buf3, msg.words[1], remote_cap, VREGION_FLAGS_READ_WRITE);
            int status = *((int *) buf3);
            domainid_t pid = ((int*)buf3)[1];
            proc_mgmt_terminated(pid, status);
            err = lmp_chan_register_send(rpc->channel, get_default_waitset(), MKCLOSURE(send_ack_handler, (void*) rpc));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "registering send handler\n");
                return;
            }
            break;
        case SPAWN_WITH_CAPS_MSG:
            // debug_printf("is spawn with caps message\n");
        
            void *buf14;
            err = paging_map_frame_attr(get_current_paging_state(), &buf14, msg.words[1], remote_cap, VREGION_FLAGS_READ_WRITE);
            struct spawn_with_caps_frame_input * input = (struct spawn_with_caps_frame_input*) buf14;
            char ** argv = malloc(4096);
            for (int i = 0; i < input->argc; i++) {
                argv[i] = malloc(strlen(input->argv[i] + 1));
                strcpy(argv[i], input->argv[i]);
            }
            domainid_t pid4;
            err = proc_mgmt_spawn_with_caps(input->argc, (const char **) argv, input->capc, &input->cap, input->core, &pid4);
            (input->pid) = pid4;
            if (err_is_fail(err)) {
                debug_printf("spawn with caps failed\n");
            }
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


    // TODO: allocate only when needed
    err = lmp_chan_alloc_recv_slot(rpc->channel);
}

/**
 *  Entry point for the bootstrap processor (BSP),
 *  which is the primary processor that initializes the system and brings up the other cores.
 *  1. Initializing system resources (e.g., memory, UMP channels, and process manager).
    2. Spawning and booting other cores (APs).
    3. Acting as a monitor for inter-core communication.

    centralized manager
 */
static int
bsp_main(int argc, char *argv[]) {
    debug_printf("In the bsp_main\n");
    errval_t err;
    initialize_process_manager(&proc_manager);

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

    debug_printf("start other cores\n");
    switch (platform_info.platform) {
        case PI_PLATFORM_IMX8X: {
            // SPAWN THE SECOND CORE on the IMX8X baord
            // hwid_t mpid = 1;
            // err = coreboot_boot_core(mpid, "boot_armv8_generic", "cpu_imx8x", "init", NULL);
            err = coreboot_boot_core(1, "boot_armv8_generic", "cpu_imx8x", "init", NULL);
            err = coreboot_boot_core(2, "boot_armv8_generic", "cpu_imx8x", "init", NULL);
            err = coreboot_boot_core(3, "boot_armv8_generic", "cpu_imx8x", "init", NULL);
            break;
        }
        case PI_PLATFORM_QEMU: {
            // SPAWN THE SECOND CORE on QEMU
            // hwid_t mpid = 1;
            // err = coreboot_boot_core(mpid, "boot_armv8_generic", "cpu_a57_qemu", "init", NULL);
            err = coreboot_boot_core(1, "boot_armv8_generic", "cpu_a57_qemu", "init", NULL);
            err = coreboot_boot_core(2, "boot_armv8_generic", "cpu_a57_qemu", "init", NULL);
            err = coreboot_boot_core(3, "boot_armv8_generic", "cpu_a57_qemu", "init", NULL);
            break;
        }
        default:
            debug_printf("Unsupported platform\n");
            return LIB_ERR_NOT_IMPLEMENTED;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Booting second core failed. Continuing.\n");
    }

    debug_printf("Prepare to set up the UMP channel\n");

    // Spawn system processes, boot second core etc. here
    // initialize UMP channels
    for (int i = 1; i < 4; i++) {
        genvaddr_t ump_addr = (genvaddr_t)get_channel_for_core_to_monitor(i, 0);
        ump_chan_init((struct ump_chan *)ump_addr, ROUND_UP(ump_addr, BASE_PAGE_SIZE) - ump_addr);
        ump_addr = (genvaddr_t)get_channel_for_core_to_monitor(i, 1);
        ump_chan_init((struct ump_chan *)ump_addr, ROUND_UP(ump_addr, BASE_PAGE_SIZE) - ump_addr + BASE_PAGE_SIZE);
    }


    // calling late grading tests, required functionality up to here:
    //   - full functionality of the system
    // DO NOT REMOVE THE FOLLOWING LINE!
    grading_test_late();

    debug_printf("Message handler loop\n");


    // BSP continuously handles events registered with its waitset
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        debug_printf("get into the loop\n");
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }

        // dispatch on URPC
        genvaddr_t urpc_base = (genvaddr_t) bi;
        (void)urpc_base;

    // The BSP monitors incoming UMP messages from other cores.
    // i = 1 to 3 is all cores it is monitoring
     for (int i = 1; i < 4; i++) {
        debug_printf("Checking for UMP messages from core %d\n", i);

        struct ump_payload payload;

        // cpre to monitor
        err = ump_receive(get_channel_for_core_to_monitor(i, 0), &payload);

        if (err == SYS_ERR_OK) {
            debug_printf("UMP message received from core %d\n", i);
            debug_printf("Message type: %d, Core: %d\n", payload.type, payload.core);

            switch (payload.type) {
                case SPAWN_CMDLINE:
                    debug_printf("Message type: SPAWN_CMDLINE from core %d\n", i);
                    domainid_t pid;
                    debug_printf("Attempting to spawn a new process with payload: '%s'\n", payload.payload);

                    err = proc_mgmt_spawn_with_cmdline(payload.payload, payload.core, &pid);
                    if (err_is_fail(err)) {
                        debug_printf("Failed to spawn process on core %d with error: %s\n", payload.core, err_getstring(err));
                        abort();
                    }

                    debug_printf("Successfully spawned a process with PID %d on core %d\n", pid, payload.core);
                    thread_yield();  // Allow other threads to execute
                    break;

                default:
                    debug_printf("Received unknown UMP message type: %d from core %d\n", payload.type, i);
            }
        } else if (err != SYS_ERR_OK) {
            debug_printf("No valid UMP message received from core %d. Error: %s\n", i, err_getstring(err));
        } else {
            debug_printf("No new messages from core %d during this iteration.\n", i);
        }
    }


        thread_yield();

    }

    // spawn the shell
    domainid_t shell_pid;
    proc_mgmt_spawn_with_cmdline("shell", 0, &shell_pid);

    return main_loop(get_default_waitset());

    return EXIT_SUCCESS;
}

/**
 * Entry point for secondary cores. 
 * These cores rely on the BSP for initialization and focus on setting up their local environment for operation
 * 
 *  Application-specific tasks and rely on the BSP for high-level management
 *  APs handle distributed workloads
 */
static int
app_main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    errval_t err;

    // Creating the Module Root CNode
    struct capref module_cnode_cslot = {
        .cnode = cnode_root,
        .slot = ROOTCN_SLOT_MODULECN
    };

    /**
     * The primary core (BSP) prepares the modules and their associated memory regions. 
     * To make these available to the secondary cores, a dedicated CNode is created to store capabilities pointing to the modules.
     * Secondary core may need to load and execute modules (like the init process or other binaries) as part of its startup
     */
    struct cnoderef module_cnode_ref;
    err = cnode_create_raw(module_cnode_cslot, &module_cnode_ref, ObjType_L2CNode, L2_CNODE_SLOTS);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create elf module root on new core");
        abort();
    }

    // Mapping the URPC Frame
    // The shared memory region is used for inter-core communication using URPC 
    err = paging_map_frame_attr(get_current_paging_state(), &urpc_buf, 4 * BASE_PAGE_SIZE,
    cap_urpc, VREGION_FLAGS_READ_WRITE);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "app_main: couldn't map urpc framee");
        abort();
    }

    // bootinfo is stored in the URPC frame, need this for General system metadata needed during initialization.
    bi = (struct bootinfo*) urpc_buf;          

    /**
     * The BSP core defines and sets up memory regions for all cores using the bootinfo structure. 
     * These regions are distributed to secondary cores via capability forgeries.
     * 
     *  ram_forge assigns a physical base address (mr_base) and a size (mr_bytes) of memory to the secondary core, extracted from the bootinfo structure.
        Each secondary core thus knows which part of memory it owns, as the BSP core allocates and shares memory capabilities for individual cores.

        It assigns ownership of this memory region to the secondary core so that it can use the RAM for its own processes and data
     * 
     */
    struct capref ram_cap = {
        .cnode = cnode_memory,
        .slot = 0
    };

    /**
     * forges a capability for each module (e.g., ELF binaries or data segments) listed in the bootinfo. 
     * It allows the secondary core to access these modules for loading or execution.
     */
    err = ram_forge(ram_cap, bi->regions[0].mr_base, bi->regions[0].mr_bytes, my_core_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "couldn't get ram from other core");
        abort();
    }

    // Forge caps to every module
    /**
     * forges a capability for each module (e.g., ELF binaries or data segments) listed in the bootinfo. 
     * It allows the secondary core to access these modules for loading or execution.
     */
    for (int i = 1; i < (int) bi->regions_length; i++) {
        struct capref module_cap = {
            .cnode = cnode_module,
            .slot = bi->regions[i].mrmod_slot,
        };
       
        err = frame_forge(module_cap, bi->regions[i].mr_base, 
                          ROUND_UP(bi->regions[i].mrmod_size, BASE_PAGE_SIZE), my_core_id);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "couldn't get ram from other core");
            abort();
        }                 
      
    }

    // Forge cap to module strings, so secondary cores can retrieve and use the module strings.
    /** 
     * module strings contain metadata about ELF binaries (e.g., names, paths, and descriptions).
     * These are required by secondary cores (APs) to locate, load, and execute modules such as the init process.
     */
    genpaddr_t* base = urpc_buf + sizeof(struct bootinfo) + ((bi->regions_length) * sizeof(struct mem_region));
    gensize_t* bytes = urpc_buf + sizeof(struct bootinfo) + ((bi->regions_length) * sizeof(struct mem_region)) + sizeof(genpaddr_t);
    err = frame_forge(cap_mmstrings, *base, ROUND_UP(*bytes, BASE_PAGE_SIZE), my_core_id);
  

                      
    // TODO (M5):
    //   - initialize memory allocator etc.
    //   - obtain a pointer to the bootinfo structure on the appcore!
    err = initialize_ram_alloc(bi);
    if(err_is_fail(err)){
        USER_PANIC_ERR(err, "initialize_ram_alloc");
    }

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
    for (int i = 0; i < (int) bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Module) {
            const char* name = multiboot_module_name(&bi->regions[i]);
            strncpy(mod_names[num_mod_names], name, MOD_NAME_LEN);
            // debug_printf("added module: %s\n", mod_names[num_mod_names]);
            num_mod_names++;
        }
    }

    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch_non_block(default_ws);

        if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }

        // check for a UMP message
        struct ump_payload payload;
        err = ump_receive(get_channel_for_current_core(1), &payload);
        if (err == SYS_ERR_OK) {
            switch (payload.type) {
                case SPAWN_CMDLINE:
                    domainid_t pid;
                    err = proc_mgmt_spawn_with_cmdline(payload.payload, disp_get_core_id(), &pid);
                    if (err_is_fail(err)) {
                        debug_printf("couldn't spawn a process\n");
                        abort();
                    }
                    debug_printf("succrssfully spawn a process in app_main\n");
                    thread_yield();
                    break;
                default:
                    debug_printf("received unknown UMP message type\n");
            }
        }

        thread_yield();

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
