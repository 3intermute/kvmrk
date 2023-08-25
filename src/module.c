#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/memory.h>

#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kconfig.h>

#include <asm/thread_info.h>

#include "include/kvmrk.h"
#include "include/resolve_kallsyms.h"
#include "include/assembler.h"
#include "include/set_page_flags.h"
#include "include/helpers.h"

static struct kvm_host_data *host_data_per_cpu;
static unsigned long **hyp_stack_per_cpu;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wintermute");
MODULE_DESCRIPTION("FUCKKKK");
MODULE_VERSION("0.01");


// force 64k pages via alignment via __attribute__((optimize("align-functions=4096"))) ???
__attribute__((align(4096))) static void __kvmrk_handle_trap(struct kvm_cpu_context *host_ctxt) {
    u64 esr = read_sysreg_el2(SYS_ESR);

    switch (ESR_ELx_EC(esr)) {
        case ESR_ELx_EC_HVC64: {
            host_ctxt->sys_regs[0] = 0x333;
            break;
        }
    	case ESR_ELx_EC_CP14_MR: {
            break;
        }
	}

    return;
}

static void fixup__kvmrk_vectors(void *_kvmrk_vectors) {
    printk(KERN_INFO "kvmrk: fixup__kvmrk_vectors(%lx)\n", _kvmrk_vectors);

    // copy pa of host_data_per_cpu to __kvmrk_vectors __fixup_1
    host_data_per_cpu = kmalloc(sizeof(struct kvm_host_data) * num_online_cpus(), GFP_KERNEL);
    phys_addr_t host_data_per_cpu_pa = virt_to_phys(host_data_per_cpu);
    printk(KERN_INFO "kvmrk:    host_data_per_cpu @ PA %lx\n", host_data_per_cpu_pa);

    memcpy(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_1), &host_data_per_cpu_pa, sizeof(unsigned long));
    helper_for_each_cpu(helper_flush_virt(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_1));)


    // copy branch to __kvmrk_handle_trap, use highmem version for now because i am lazy
    uint32_t shellcode_br[5];
    assemble_absolute_load(18, highmem_virt_to_phys(__kvmrk_handle_trap), shellcode_br);
    shellcode_br[4] = cpu_to_le32(0xd63f0240); // blr x18 "\x40\x02\x3f\xd6"

    // memcpy(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2), shellcode_br, 5 * INS_WIDTH);
    helper_for_each_cpu(helper_flush_virt(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2));)
}

static void *copy___kvmrk_vectors(void) {
    // copy __kvmrk_vectors to phys contig lowmem THEN fixup
    printk(KERN_INFO "kvmrk: copy___kvmrk_vectors()\n");

    void *_kvmrk_vectors = helper_make_contig(__kvmrk_vectors, __kvmrk_vectors_end - __kvmrk_vectors);
    helper_for_each_cpu(helper_flush_virt(_kvmrk_vectors);)
    fixup__kvmrk_vectors(_kvmrk_vectors);
    helper_for_each_cpu(helper_flush_virt(_kvmrk_vectors);)

    printk(KERN_INFO "kvmrk:    _kvmrk_vectors @ VA %lx\n", _kvmrk_vectors);
    printk(KERN_INFO "kvmrk:    addr__kvmrk_vectors(_kvmrk_vectors, __fixup_1) %lx\n", addr__kvmrk_vectors(_kvmrk_vectors, __fixup_1));
    printk(KERN_INFO "kvmrk:    _kvmrk_vectors @ PA %lx\n", virt_to_phys(_kvmrk_vectors));
    printk(KERN_INFO "kvmrk:    FIXED __fixup_1 -> host_data_per_cpu PA is %lx\n", *((uint64_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_1))));
    printk(KERN_INFO "kvmrk:    FIXED __fixup_2 -> b __kvmrk_handle_trap (PA %lx) is\n", highmem_virt_to_phys(__kvmrk_handle_trap));
    printk(KERN_INFO "kvmrk:        %x\n", *((uint32_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2))));
    printk(KERN_INFO "kvmrk:        %x\n", *((uint32_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2) + INS_WIDTH)));
    printk(KERN_INFO "kvmrk:        %x\n", *((uint32_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2) + INS_WIDTH * 2)));
    printk(KERN_INFO "kvmrk:        %x\n", *((uint32_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2) + INS_WIDTH * 3)));
    printk(KERN_INFO "kvmrk:        %x\n", *((uint32_t *)(addr__kvmrk_vectors(_kvmrk_vectors, __fixup_2) + INS_WIDTH * 4)));

    return _kvmrk_vectors;
}

static int __init kvmrk_init(void) {
    printk(KERN_INFO "kvmrk: module loaded\n");
    init_init_mm_ptr();


    void *_kvmrk_vectors = copy___kvmrk_vectors();
    // try uncommenting this if something breaks
    // helper_for_each_cpu(helper_flush_virt(_kvmrk_vectors);)

    printk(KERN_INFO "kvmrk: try init cpu context on all cpus\n");
    helper_for_each_cpu(\
        helper_init_host_cpu_context(&(kvmrk_this_cpu(host_data_per_cpu).host_ctxt)); \
        printk(KERN_INFO "kvmrk:    host_data for cpu %i @ VA %lx\n", kvmrk_get_smp_processor_id, kvmrk_this_cpu_ptr(host_data_per_cpu)); \
    )

    printk(KERN_INFO "kvmrk: try reset vectors on all cpus to _hyp_stub_vectors\n");
    helper_for_each_cpu(kvmrk_reset_vectors();)

    printk(KERN_INFO "kvmrk: try set vbar_el2 on all cpus to __kvmrk_stub_vectors, @ PA %lx\n", highmem_virt_to_phys(__kvmrk_stub_vectors));
    helper_for_each_cpu(kvmrk_set_vectors(highmem_virt_to_phys(__kvmrk_stub_vectors));)

    hyp_stack_per_cpu = kmalloc(sizeof(unsigned long) * num_online_cpus(), GFP_KERNEL);
    helper_for_each_cpu(\
        kvmrk_this_cpu(hyp_stack_per_cpu) = kmalloc(KVMRK_HYP_STACK_SIZE, GFP_KERNEL); \
        printk(KERN_INFO "kvmrk: stack allocated for cpu %i @ VA %lx, PA %lx\n", kvmrk_get_smp_processor_id, kvmrk_this_cpu(hyp_stack_per_cpu), virt_to_phys(kvmrk_this_cpu(hyp_stack_per_cpu))); \
    )
    helper_for_each_cpu(helper_flush_virt(hyp_stack_per_cpu);)

    helper_for_each_cpu(\
        unsigned long x = kvmrk_hvc(KVMRK_HVC_INIT_VECTORS, \
                                    virt_to_phys(_kvmrk_vectors), \
                                    virt_to_phys(kvmrk_this_cpu(hyp_stack_per_cpu)), \
                                    NULL); \
        printk(KERN_INFO "kvmrk: KVMRK_HVC_INIT_VECTORS for cpu %i returned %lx\n", kvmrk_get_smp_processor_id, x); \
    )

    printk(KERN_INFO "kvmrk: hvc returned %lx\n", kvmrk_hvc(NULL, NULL, NULL, NULL));

    // kvmrk_hvc(KVMRK_CALL_HYP, highmem_virt_to_phys(__hijack_mdcr_el2), NULL, NULL);
    // register unsigned long r2 asm("x0");
    // printk(KERN_INFO "kvmrk: KVMRK_CALL_HYP returned %lx\n", r2);
    //
    // asm volatile("mrs x0, dbgbcr0_el1");
    // register unsigned long r3 asm("x0");
    // printk(KERN_INFO "kvmrk: read dbgbcr0_el1 returned %lx\n", r3);

    return 0;
}

static void __exit kvmrk_exit(void) {
    printk(KERN_INFO "kvmrk: module unloaded\n");
}

module_init(kvmrk_init);
module_exit(kvmrk_exit);
