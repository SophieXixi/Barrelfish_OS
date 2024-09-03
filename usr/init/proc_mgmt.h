/*
 * Copyright (c) 2022 The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef INIT_PROC_MGMT_H_
#define INIT_PROC_MGMT_H_ 1

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <proc_mgmt/proc_mgmt.h>





/**
 * @brief terminates the process in respose to an exit message
 *
 * @param[in] pid     the PID of the process to be terminated
 * @param[in] status  exit code
 *
 * @return SYS_ERR_OK on sucess, error value on failure
 */
errval_t proc_mgmt_terminated(domainid_t pid, int status);

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
                                 struct waitset *ws);

#endif /* INIT_PROC_MGMT_H_ */