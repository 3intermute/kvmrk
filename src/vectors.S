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


.align 12
SYM_CODE_START(__kvmrk_stub_vectors)
	ventry	__invalid_stub_vect		// Synchronous EL2t
	ventry	__invalid_stub_vect		// IRQ EL2t
	ventry	__invalid_stub_vect		// FIQ EL2t
	ventry	__invalid_stub_vect		// Error EL2t

	ventry	__invalid_stub_vect		// Synchronous EL2h
	ventry	__invalid_stub_vect		// IRQ EL2h
	ventry	__invalid_stub_vect		// FIQ EL2h
	ventry	__invalid_stub_vect		// Error EL2h

	ventry	__kvmrk_stub_el1_sync	// Synchronous 64-bit EL1
	ventry	__invalid_stub_vect		// IRQ 64-bit EL1
	ventry	__invalid_stub_vect		// FIQ 64-bit EL1
	ventry	__invalid_stub_vect		// Error 64-bit EL1

	ventry	__invalid_stub_vect		// Synchronous 32-bit EL1
	ventry	__invalid_stub_vect		// IRQ 32-bit EL1
	ventry	__invalid_stub_vect		// FIQ 32-bit EL1
	ventry	__invalid_stub_vect		// Error 32-bit EL1

__invalid_stub_vect:
	b	.
__kvmrk_stub_el1_sync:
// x0 = KVMRK_INIT_VECTORS: x1 = new vbar_el2, x2 = sp_el2
	/*
	mrs		x18, esr_el2
	lsr		x18, x18, #ESR_ELx_EC_SHIFT
	cmp		x18, #ESR_ELx_EC_HVC64
	bne 	__bad_exit
	*/

	cmp	    x0, #KVMRK_HVC_INIT_VECTORS
	bne		__bad_exit
	msr 	vbar_el2, x1
	mov 	sp, x2
	// msr		spsel, 1 // C5.2.16
	mov 	x0, sp
	eret
__bad_exit:
	mov_q	x0, 0xdeadca11
	eret
SYM_CODE_END(__kvmrk_stub_vectors)
kvmrk_end __kvmrk_stub_vectors_end



.align	12
SYM_CODE_START(__kvmrk_vectors)
	ventry	__invalid_vect		// Synchronous EL2t
	ventry	__invalid_vect		// IRQ EL2t
	ventry	__invalid_vect		// FIQ EL2t
	ventry	__invalid_vect		// Error EL2t

	ventry	__invalid_vect		// Synchronous EL2h
	ventry	__invalid_vect		// IRQ EL2h
	ventry	__invalid_vect		// FIQ EL2h
	ventry	__invalid_vect		// Error EL2h

	ventry	__kvmrk_el1_sync		// Synchronous 64-bit EL1
	ventry	__invalid_vect		// IRQ 64-bit EL1
	ventry	__invalid_vect		// FIQ 64-bit EL1
	ventry	__invalid_vect		// Error 64-bit EL1

	ventry	__invalid_vect		// Synchronous 32-bit EL1
	ventry	__invalid_vect		// IRQ 32-bit EL1
	ventry	__invalid_vect		// FIQ 32-bit EL1
	ventry	__invalid_vect		// Error 32-bit EL1

__invalid_vect:
	b 	.
__kvmrk_el1_sync:
	stp	x0, x1, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!

	/*
	// https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/kvm/hyp/nvhe/host.S#L116
	mrs	x0, esr_el2
	lsr	x0, x0, #ESR_ELx_EC_SHIFT
	kvm_get_host_ctxt	x0, x1
	*/

	b __fixup_1_end

// enable mmu, skidrip linux kernel
.globl __fixup_1
__fixup_1:
	nop
	nop
__fixup_1_end:
	ldr 	x0, __fixup_1
	ldr		x0, [x0]
	mrs 	x1, mpidr_el1
	// https://elixir.bootlin.com/linux/latest/source/arch/arm/include/asm/cputype.h#L54
	mov_q 	x2, 0xffffff // MPIDR_HWID_BITMASK
	and   	x1, x1, x2
	mov     x2, #SIZEOF_KVM_HOST_DATA
	madd	x0, x1, x2, x0

	add x0, x0, #HOST_DATA_CONTEXT

	ldp	x2, x3, [sp], #16	// orig x2, x3

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

.globl __fixup_2
__fixup_2:
	// placeholder to copy branch to kvmrk_handle_trap pa
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
SYM_CODE_END(__kvmrk_vectors)
kvmrk_end __kvmrk_vectors_end

.align 12
SYM_CODE_START(__hijack_mdcr_el2)
	/*
	mrs 	x0, mdcr_el2
	orr 	x0, x0, #MDCR_EL2_TDA
	msr 	mdcr_el2, x0
	mov_q	x0, 0x333
	*/
	eret
SYM_CODE_END(__hijack_mdcr_el2)
kvmrk_end __hijack_mdcr_el2_end














SYM_FUNC_START(kvmrk_hvc)
	hvc     #0
	ret
SYM_FUNC_END(kvmrk_hvc)

SYM_FUNC_START(_helper_flush_virt)
	dc 		cvac, x0
	ret
SYM_FUNC_END(_helper_flush_virt)

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
