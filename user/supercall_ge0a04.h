/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include "../version"

#include "uapi/scdefs.h"

static inline long ver_and_cmd(const char *key, long cmd)
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x2026 << 16) | (cmd & 0xFFFF);
}

static inline long sc_hello(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_HELLO));
    return ret;
}

static inline bool sc_ready(const char *key)
{
    return sc_hello(key) == SUPERCALL_HELLO_MAGIC;
}

static inline long sc_klog(const char *key, const char *msg)
{
    if (!key || !key[0]) return -EINVAL;
    if (!msg || strlen(msg) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KLOG), msg);
    return ret;
}

static inline uint32_t sc_kp_ver(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KERNELPATCH_VER));
    return (uint32_t)ret;
}

static inline uint32_t sc_k_ver(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KERNEL_VER));
    return (uint32_t)ret;
}

static inline uint32_t sc_skey_get(const char *key, char *out_key, int outlen)
{
    if (!key || !key[0]) return -EINVAL;
    if (outlen < SUPERCALL_KEY_MAX_LEN) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_SKEY_GET), out_key, outlen);
    return (uint32_t)ret;
}

static inline uint32_t sc_skey_set(const char *key, const char *new_key)
{
    if (!key || !key[0]) return -EINVAL;
    if (!new_key || !new_key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_SKEY_SET), new_key);
    return (uint32_t)ret;
}

static inline uint32_t sc_skey_root_enable(const char *key, bool enable)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_SKEY_ROOT_ENABLE), (long)enable);
    return (uint32_t)ret;
}

static inline long sc_kpm_load(const char *key, const char *path, const char *args, void *reserved)
{
    if (!key || !key[0]) return -EINVAL;
    if (!path || strlen(path) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_LOAD), path, args, reserved);
    return ret;
}

static inline long sc_kpm_control(const char *key, const char *name, const char *ctl_args, char *out_msg, long outlen)
{
    if (!key || !key[0]) return -EINVAL;
    if (!name || strlen(name) <= 0) return -EINVAL;
    if (!ctl_args || strlen(ctl_args) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_CONTROL), name, ctl_args, out_msg, outlen);
    return ret;
}

static inline long sc_kpm_unload(const char *key, const char *name, void *reserved)
{
    if (!key || !key[0]) return -EINVAL;
    if (!name || strlen(name) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_UNLOAD), name, reserved);
    return ret;
}

static inline long sc_kpm_nums(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_NUMS));
    return ret;
}

static inline long sc_kpm_list(const char *key, char *names_buf, int buf_len)
{
    if (!key || !key[0]) return -EINVAL;
    if (!names_buf || buf_len <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_LIST), names_buf, buf_len);
    return ret;
}

static inline long sc_kpm_info(const char *key, const char *name, char *buf, int buf_len)
{
    if (!key || !key[0]) return -EINVAL;
    if (!buf || buf_len <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_INFO), name, buf, buf_len);
    return ret;
}

static inline long sc_bootlog(const char *key)
{
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_BOOTLOG));
    return ret;
}

static inline long sc_panic(const char *key)
{
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_PANIC));
    return ret;
}

static inline long sc_kstorage_read(const char *key, int gid, long did, void *out_data, int offset, int dlen)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KSTORAGE_READ), gid, did, out_data, (((long)offset << 32) | dlen));
    return ret;
}

static inline long sc_kstorage_write(const char *key, int gid, long did, void *data, int offset, int dlen)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KSTORAGE_WRITE), gid, did, data, (((long)offset << 32) | dlen));
    return ret;
}

static inline long sc_kstorage_remove(const char *key, int gid, long did)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KSTORAGE_REMOVE), gid, did);
    return ret;
}

static inline long sc_set_ap_mod_exclude(const char *key, uid_t uid, int exclude)
{
    if(exclude) {
        return sc_kstorage_write(key, KSTORAGE_EXCLUDE_LIST_GROUP, uid, &exclude, 0, sizeof(exclude));
    } else {
        return sc_kstorage_remove(key, KSTORAGE_EXCLUDE_LIST_GROUP, uid);
    }
}

static inline int sc_get_ap_mod_exclude(const char *key, uid_t uid)
{
    int exclude = 0;
    int rc = sc_kstorage_read(key, KSTORAGE_EXCLUDE_LIST_GROUP, uid, &exclude, 0, sizeof(exclude));
    if (rc < 0) return 0;
    return exclude;
}

#endif