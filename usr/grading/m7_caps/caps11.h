/*
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#define CAPS11_NCAPS 9

#include <aos/cache.h>


#define REVOKE_CAP_1 3
#define REVOKE_CAP_2 4
#define REVOKE_CAP_3 5
#define REVOKE_CAP_4 6
#define RETYPE_CAP_1 7
#define RETYPE_CAP_2 8

#define CAPS11_ERR      ((uint64_t)-1)
#define CAPS11_INIT     1
#define CAPS11_READY    2
#define CAPS11_DEL_1    3
#define CAPS11_DEL_2    4
#define CAPS11_REVOKE_1 5
#define CAPS11_REVOKE_2 6
#define CAPS11_REVOKE_3 7
#define CAPS11_REVOKE_4 8
#define CAPS11_RETYPE_1 9
#define CAPS11_RETYPE_2 10

static inline void CAPS_ABORT_ON_ERROR(volatile uint64_t *buf)
{
    if (*buf == CAPS11_ERR) {
        grading_printf("%s: error in remote process\n", disp_name());
        grading_stop();
    }
}

static inline void CAPS_WAIT(volatile uint64_t *buf, uint64_t state)
{
    while (*buf == state) ;
    dmb();
    CAPS_ABORT_ON_ERROR(buf);
}

static inline void CAPS_NEXT_AND_WAIT(volatile uint64_t *buf, uint64_t state)
{
    *buf = state;
    dmb();
    CAPS_WAIT(buf, state);
}