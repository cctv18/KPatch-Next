/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUPERCALL_H_
#define _KP_SUPERCALL_H_

extern void *compat_sys_call_table;
extern int has_config_compat;

void before(hook_fargs6_t *args, void *udata);

#endif
