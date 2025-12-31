/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUCOMPAT_H_
#define _KP_SUCOMPAT_H_

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>

extern const char sh_path[];

int is_su_allow_uid(uid_t uid);

int get_ap_mod_exclude(uid_t uid);
int set_ap_mod_exclude(uid_t uid, int exclude);
int list_ap_mod_exclude(uid_t *uids, int len);

#endif
