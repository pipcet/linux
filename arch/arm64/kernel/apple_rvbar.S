	.align	16
	.globl	apple_rvbar
apple_rvbar:
	b	secondary_entry
	nop
	nop
	nop
	.align	16

	.globl	apple_spin_code
apple_spin_code:
	ldr	x3, [x0]
	cbnz	x3, found
	wfe
	b	apple_spin_code
found:
	br	x3

	.align	16
