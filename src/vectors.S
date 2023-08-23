#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/el2_setup.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/ptrace.h>
#include <asm/virt.h>


#include "include/kvmrk.h"

/*
	.text
	.pushsection	.kvmrk.text, "ax"
	.align	11

SYM_CODE_START(kvmrk_vector)
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
	// mov_q	    x0, #KVMRK_STUB_SUCCESS
 	eret
SYM_CODE_END(kvmrk_vector)
*/

SYM_CODE_START(kvmrk_elx_sync)
	mov_q	x0, 0x600dca11
	eret
SYM_CODE_END(kvmrk_elx_sync)
SYM_CODE_START(kvmrk_elx_sync_end)
	nop
SYM_CODE_END(kvmrk_elx_sync_end)




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
