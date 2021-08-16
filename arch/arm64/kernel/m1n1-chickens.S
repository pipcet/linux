/* This file is derived from the MIT-licensed m1n1/chickens.c */

	.arch armv8-a
	.file	"chickens.c"
	.align	3
.LC0:
	.string	"M1 Firestorm"
	.align	3
.LC1:
	.string	"M1 Icestorm"
	.align	3
.LC2:
	.string	"Unknown"
	.align	2
	.p2align 4,,11
	.global	init_cpu
	.type	init_cpu, %function
init_cpu:
.LFB31:
	mov	x0, 0
#APP
// 102 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	OSLAR_EL1, x0
// 0 "" 2
// 326 "bootloaders/m1n1/m1n1/src/utils.h" 1
	mrs	x0, MPIDR_EL1
// 0 "" 2
#NO_APP
	tbnz	x0, 16, .L2
#APP
// 106 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c4_1
// 0 "" 2
#NO_APP
	mov	x1, 2048
	movk	x1, 0x1000, lsl 32
	orr	x0, x0, x1
#APP
// 106 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c4_1, x0
// 0 "" 2
// 110 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, MIDR_EL1
// 0 "" 2
#NO_APP
	ubfx	w0, w0, 4, 12
	cmp	w0, 34
	beq	.L4
.L8:
	cmp	w0, 35
	bne	.L6
#APP
// 53 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c0_0
// 0 "" 2
#NO_APP
	mov	x1, 268435456
	movk	x1, 0x2010, lsl 32
	orr	x0, x0, x1
#APP
// 53 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c0_0, x0
// 0 "" 2
// 57 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c1_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 18014398509481984
#APP
// 57 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c1_0, x0
// 0 "" 2
// 59 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c3_0
// 0 "" 2
#NO_APP
	and	x0, x0, 9223372036854775807
	and	x0, x0, -17592186044417
#APP
// 59 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c3_0, x0
// 0 "" 2
// 62 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c4_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 3298534883328
#APP
// 62 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c4_0, x0
// 0 "" 2
// 66 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c5_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 2305843009213693952
#APP
// 66 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c5_0, x0
// 0 "" 2
// 68 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c6_0
// 0 "" 2
#NO_APP
	and	x0, x0, -993
#APP
// 68 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c6_0, x0
// 0 "" 2
// 70 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c7_0
// 0 "" 2
#NO_APP
	mov	x1, 1114112
	orr	x0, x0, x1
#APP
// 70 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c7_0, x0
// 0 "" 2
// 73 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c7_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 50331648
#APP
// 73 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c7_0, x0
// 0 "" 2
// 76 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c9_0
// 0 "" 2
#NO_APP
	mov	x1, 603979776
	movk	x1, 0x1, lsl 48
	orr	x0, x0, x1
#APP
// 76 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c9_0, x0
// 0 "" 2
// 79 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c11_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 576460752303423488
#APP
// 79 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c11_0, x0
// 0 "" 2
// 83 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c14_0
// 0 "" 2
#NO_APP
	and	x0, x0, -245761
	orr	x0, x0, 65536
#APP
// 83 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c14_0, x0
// 0 "" 2
// 88 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c15_2
// 0 "" 2
#NO_APP
	mov	x1, 7566047373982433280
	orr	x0, x0, x1
#APP
// 88 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c15_2, x0
// 0 "" 2
// 91 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c11_2
// 0 "" 2
#NO_APP
	orr	x0, x0, 16384
#APP
// 91 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c11_2, x0
// 0 "" 2
// 93 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c1_3
// 0 "" 2
#NO_APP
	and	x0, x0, -524289
#APP
// 93 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c1_3, x0
// 0 "" 2
// 18 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, MPIDR_EL1
// 0 "" 2
#NO_APP
	and	x0, x0, 255
#APP
// 21 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_4_c15_c5_0, x0
// 0 "" 2
#NO_APP
	mov	x0, 256
#APP
// 22 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_4_c15_c1_4, x0
// 0 "" 2
// 23 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	isb
// 0 "" 2
#NO_APP
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
.L5:
#APP
// 128 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x1, s3_5_c15_c5_0
// 0 "" 2
#NO_APP
	mov	x2, -49283073
	and	x1, x1, x2
	orr	x1, x1, 33554432
#APP
// 128 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_5_c15_c5_0, x1
// 0 "" 2
// 133 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x1, s3_5_c15_c4_0
// 0 "" 2
#NO_APP
	orr	x1, x1, 12
#APP
// 133 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_5_c15_c4_0, x1
// 0 "" 2
#NO_APP
	ret
	.p2align 2,,3
.L6:
	adrp	x0, .LC2
	add	x0, x0, :lo12:.LC2
	b	.L5
	.p2align 2,,3
.L2:
#APP
// 108 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c4_0
// 0 "" 2
#NO_APP
	mov	x1, 2048
	movk	x1, 0x1000, lsl 32
	orr	x0, x0, x1
#APP
// 108 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c4_0, x0
// 0 "" 2
// 110 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, MIDR_EL1
// 0 "" 2
#NO_APP
	ubfx	w0, w0, 4, 12
	cmp	w0, 34
	bne	.L8
.L4:
#APP
// 29 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c5_0
// 0 "" 2
#NO_APP
	orr	x0, x0, 2305843009213693952
#APP
// 29 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c5_0, x0
// 0 "" 2
// 31 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c9_1
// 0 "" 2
#NO_APP
	and	x0, x0, -33
#APP
// 31 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c9_1, x0
// 0 "" 2
// 35 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c10_1
// 0 "" 2
#NO_APP
	mov	x1, 4294967296
	movk	x1, 0x2, lsl 48
	orr	x0, x0, x1
#APP
// 35 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c10_1, x0
// 0 "" 2
// 38 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c1_2
// 0 "" 2
#NO_APP
	orr	x0, x0, 256
#APP
// 38 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c1_2, x0
// 0 "" 2
// 40 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c1_2
// 0 "" 2
#NO_APP
	orr	x0, x0, 98304
#APP
// 40 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c1_2, x0
// 0 "" 2
// 43 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, s3_0_c15_c1_2
// 0 "" 2
#NO_APP
	orr	x0, x0, 6291456
#APP
// 43 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_0_c15_c1_2, x0
// 0 "" 2
// 18 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	mrs	x0, MPIDR_EL1
// 0 "" 2
#NO_APP
	and	x0, x0, 255
#APP
// 21 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_4_c15_c5_0, x0
// 0 "" 2
#NO_APP
	mov	x0, 256
#APP
// 22 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	msr	s3_4_c15_c1_4, x0
// 0 "" 2
// 23 "bootloaders/m1n1/m1n1/src/chickens.c" 1
	isb
// 0 "" 2
#NO_APP
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	b	.L5
	.size	init_cpu, .-init_cpu
