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
	.align	11

SYM_CODE_START(__kvmrk_hyp_init)
	ventry	__invalid		// Synchronous EL2t
	ventry	__invalid		// IRQ EL2t
	ventry	__invalid		// FIQ EL2t
	ventry	__invalid		// Error EL2t

	ventry	__invalid		// Synchronous EL2h
	ventry	__invalid		// IRQ EL2h
	ventry	__invalid		// FIQ EL2h
	ventry	__invalid		// Error EL2h

	ventry	__do_kvmrk_init		// Synchronous 64-bit EL1
	ventry	__invalid		// IRQ 64-bit EL1
	ventry	__invalid		// FIQ 64-bit EL1
	ventry	__invalid		// Error 64-bit EL1

	ventry	__invalid		// Synchronous 32-bit EL1
	ventry	__invalid		// IRQ 32-bit EL1
	ventry	__invalid		// FIQ 32-bit EL1
	ventry	__invalid		// Error 32-bit EL1

__invalid:
	b	.
__do_kvmrk_init:
	mov	    x0, #33
	eret
SYM_CODE_END(__kvmrk_hyp_init)

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
