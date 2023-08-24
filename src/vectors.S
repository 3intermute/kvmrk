#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/el2_setup.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

#include "include/kvmrk.h"


.text
.pushsection	.kvmrk.text, "ax"
.align	12
SYM_CODE_START(kvmrk_vectors)
	ventry	__invalid		// Synchronous EL2t
	ventry	__invalid		// IRQ EL2t
	ventry	__invalid		// FIQ EL2t
	ventry	__invalid		// Error EL2t

	ventry	__invalid		// Synchronous EL2h
	ventry	__invalid		// IRQ EL2h
	ventry	__invalid		// FIQ EL2h
	ventry	__invalid		// Error EL2h

	ventry	__do_kvmrk_el1_sync		// Synchronous 64-bit EL1
	ventry	__invalid		// IRQ 64-bit EL1
	ventry	__invalid		// FIQ 64-bit EL1
	ventry	__invalid		// Error 64-bit EL1

	ventry	__invalid		// Synchronous 32-bit EL1
	ventry	__invalid		// IRQ 32-bit EL1
	ventry	__invalid		// FIQ 32-bit EL1
	ventry	__invalid		// Error 32-bit EL1

__invalid:
	b	.
__do_kvmrk_el1_sync:
	mrs 	x18, esr_el2 // clobbers x18 bc stack isnt setup kms
	lsr 	x18, x18, #ESR_ELx_EC_SHIFT
	cmp		x18, #ESR_ELx_EC_HVC64
	b.ne	not_hypercall
1:
	// jump to handle trap, move hvc handlers into handle trap
	// leave nops to install handle trap since address isnt known at runtime ?
	cmp	    x0, #KVMRK_CALL_HYP
	bne		1f
	br 		x1
	eret
1:
	cmp 	x0, #KVMRK_CRASH_EVERYTHING
	bne 	1f
	mov		x0, xzr
	eret
1:
	cmp 	x0, #KVMRK_SET_SP
	b.ne	not_hypercall
	mov 	sp, x1
	mov		x0, x1
	eret
not_hypercall:
	// save host context
	stp	x0, x1, [sp, #-16]!
	mrs	x0, esr_el2
	lsr	x0, x0, #ESR_ELx_EC_SHIFT

	kvmrk_get_host_ctxt		x0, x1

	/* Store the host regs x2 and x3 */
	stp	x2, x3,   [x0, #CPU_XREG_OFFSET(2)]

	/* Retrieve the host regs x0-x1 from the stack */
	ldp	x2, x3, [sp], #16	// x0, x1

	/* Store the host regs x0-x1 and x4-x17 */
	stp	x2, x3,   [x0, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x0, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x0, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x0, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x0, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x0, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x0, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x0, #CPU_XREG_OFFSET(16)]

	/* Store the host regs x18-x29, lr */
	save_callee_saved_regs x0

	/* Save the host context pointer in x29 across the function call */
	mov	x29, x0

.globl copy_here_start
copy_here_start:
	// placeholder to copy lame jump
	nop
	nop
	nop
	nop
	nop

	/* Restore host regs x0-x17 */
__host_enter_restore_full:
	ldp	x0, x1,   [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x29, #CPU_XREG_OFFSET(6)]

	/* x0-7 are use for panic arguments */
__host_enter_for_panic:
	ldp	x8, x9,   [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]

	/* Restore host regs x18-x29, lr */
	restore_callee_saved_regs x29

	/* Do not touch any register after this! */
__host_enter_without_restoring:
	eret
	sb
SYM_CODE_END(kvmrk_vectors)

.align 12
SYM_CODE_START(hijack_mdcr_el2)
	mrs 	x0, mdcr_el2
	orr 	x0, x0, #MDCR_EL2_TDA
	msr 	mdcr_el2, x0
	mov_q	x0, 0xdeadbeef
	eret
SYM_CODE_END(hijack_mdcr_el2)














SYM_FUNC_START(kvmrk_hvc)
	hvc     #0
	ret
SYM_FUNC_END(kvmrk_hvc)

SYM_FUNC_START(kvmrk_flush_virt)
	dc 		cvac, x0
	ret
SYM_FUNC_END(kvmrk_flush_virt)

SYM_FUNC_START(kvmrk_set_vectors)
	mov		x1, x0
	mov		x0, #HVC_SET_VECTORS
	hvc		#0
	ret
SYM_FUNC_END(kvmrk_set_vectors)

SYM_FUNC_START(kvmrk_reset_vectors)
	mov		x0, #HVC_RESET_VECTORS
	hvc		#0
	ret
SYM_FUNC_END(kvmrk_reset_vectors)


.popsection
