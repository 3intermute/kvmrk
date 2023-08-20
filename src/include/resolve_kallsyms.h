/****************************************************************************
 * Copyright (C) 2023 by wintermute                                         *
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
 * @file resolve_ksyms.h
 * @author wintermute
 * @date 5/20/2023
 * @brief provides a wrapper to use kallsyms_lookup_name as it is not exported
 */

#ifndef _RESOLVE_KALLSYMS_H_
#define _RESOLVE_KALLSYMS_H_

#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/unistd.h>

static unsigned long (*rk_kallsyms_lookup_name_internal)(const char *) = NULL;

/**
 * @brief finds the address of a kernel function via kprobes
 *
 * used internally to find the address of kallsyms_lookup_name.
 *
 * @param func_name function name
 * @return address of function
 */
unsigned long rk_kprobe_get_func_addr(const char *func_name) {
    if (!func_name) {
        return -ENOENT;
    }

    static struct kprobe kp;
    kp.symbol_name = func_name;
    if (register_kprobe(&kp) < 0) {
        printk(KERN_DEBUG "resolve_kallsyms: register_kprobe for func %s failed\n", func_name);
        return -ENOENT;
    }

    unsigned long tmp = kp.addr;
    unregister_kprobe(&kp);
    printk(KERN_DEBUG "resolve_kallsyms: register_kprobe found func %s @ %pK\n", func_name, tmp);
    return tmp;
}

/**
 * @brief finds the address of a kernel symbol via kallsyms_lookup_name
 *
 * @param symbol_name symbol name
 * @return address of symbol
 */
unsigned long rk_kallsyms_lookup_name(const char *symbol_name) {
    if (!symbol_name) {
        return -ENOENT;
    }

    if (!rk_kallsyms_lookup_name_internal) {
        rk_kallsyms_lookup_name_internal = rk_kprobe_get_func_addr("kallsyms_lookup_name");
    }

    unsigned long tmp = rk_kallsyms_lookup_name_internal(symbol_name);
    printk(KERN_DEBUG "resolve_kallsyms: kallsyms_lookup_name found func %s @ %pK\n", symbol_name, tmp);
    return tmp;
}

#endif
