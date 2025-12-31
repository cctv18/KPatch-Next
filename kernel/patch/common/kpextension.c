/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <kpextension.h>
#include <symbol.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";
    struct su_profile profile = {
        uid,
        to_uid,
    };
    memcpy(profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);
    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(struct su_profile), false);
    logkfd("uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, scontext, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int is_su_allow_uid(uid_t uid)
{
    int rc = 0;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0)
        goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = (profile->uid == uid);

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

int kpextension_init()
{
    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

    su_add_allow_uid(0, 0, all_allow_sctx);

    return 0;
}