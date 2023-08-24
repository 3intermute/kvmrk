#ifndef _KVMRK_H_
#define _KVMRK_H_

#define KVMRK_CALL_HYP              11
#define KVMRK_RESET_VECTORS         12
#define KVMRK_CRASH_EVERYTHING      13
#define KVMRK_SET_SP                14
#define KVMRK_INS_WIDTH             4

#define KVMRK_HYP_STACK_SIZE        PAGE_SIZE * 4


#ifndef __ASSEMBLY__
DECLARE_PER_CPU(struct kvm_host_data, kvmrk_host_data);

extern void kvmrk_flush_virt(void *);
extern void kvmrk_set_vectors(phys_addr_t phys_vector_base);
extern int kvmrk_reset_vectors(void);
extern void kvmrk_vectors(void);
extern void kvmrk_vectors_end(void);

extern void copy_here_start(void);

extern void hijack_mdcr_el2(void);
extern void hijack_mdcr_el2_end(void);
extern void kvmrk_hvc(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3);

#else /* __ASSEMBLY__ */
.macro kvmrk_get_host_ctxt reg, tmp
	adr_this_cpu \reg, kvmrk_host_data, \tmp
	add	\reg, \reg, #HOST_DATA_CONTEXT
.endm

.macro kvmrk_end label
	SYM_CODE_START(\label)
		nop
	SYM_CODE_END(\label)
.endm
#endif

#endif
