#ifndef _KVMRK_H_
#define _KVMRK_H_

// #define KVMRK_HVC_CALL_HYP              11
// #define KVMRK_HVC_RESET_VECTORS         12
// #define KVMRK_HVC_CRASH_EVERYTHING      13
// #define KVMRK_HVC_SET_SP                14
#define KVMRK_HVC_INIT_VECTORS          15

#define INS_WIDTH 4

#define KVMRK_HYP_STACK_SIZE        PAGE_SIZE * 4
#define SIZEOF_KVM_HOST_DATA        1840


#ifndef __ASSEMBLY__
extern void _helper_flush_virt(void *);

extern unsigned long kvmrk_hvc(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3);
extern void kvmrk_set_vectors(phys_addr_t phys_vector_base);
extern int kvmrk_reset_vectors(void);

extern void __kvmrk_stub_vectors(void);
extern void __kvmrk_stub_vectors_end(void);
extern void __kvmrk_vectors(void);
extern void __kvmrk_vectors_end(void);

extern void __fixup_1(void);
extern void __fixup_2(void);

// .align 12 is fine for KVMRK_CALL_HYP shellcode since its likely < page size
extern void __hijack_mdcr_el2(void);
extern void __hijack_mdcr_el2_end(void);

#define offset___kvmrk_vectors(sym) \
                            ((unsigned long) sym - (unsigned long) __kvmrk_vectors)
#define addr__kvmrk_vectors(_kvmrk_vectors_base, sym) \
                            ((unsigned long) _kvmrk_vectors_base + (unsigned long) offset___kvmrk_vectors(sym))

#define kvmrk_get_smp_processor_id  (read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK)

// cpus may not be contig ??
#define kvmrk_this_cpu(x)       (x[kvmrk_get_smp_processor_id])
#define kvmrk_this_cpu_ptr(x)   (&(x[kvmrk_get_smp_processor_id]))

#else /* __ASSEMBLY__ */

.macro kvmrk_end label
	SYM_CODE_START(\label)
		nop
	SYM_CODE_END(\label)
.endm
#endif

#endif
