	.arch armv8-a
	.file	"chall_3.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	w0, [x29, 28] a_28 = w0 = arg
	str	wzr, [x29, 44] b_44 = 0
	b	.L2
.L4:
	ldr	w0, [x29, 28] w0 = arg
	and	w0, w0, 1 ; w0 AND 1 = 1 hvis oddetal, 0 hvis partall (w0 % 2 == 0?)
	cmp	w0, 0 ; w0 == 0 ?
	beq	.L3 ; branch if equal

	ldr	w0, [x29, 44] w0 = b_44
	bl	func2 ; call func2 (w0 += 3)
	str	w0, [x29, 44] b_44 = w0
.L3:
	ldr	w0, [x29, 28] ; w0 = a_28
	lsr	w0, w0, 1 ; w0 logical shift right (w0 / 2)
	str	w0, [x29, 28] ; a_28 = w0
.L2:
	ldr	w0, [x29, 28] w0 = a_28 = arg
	cmp	w0, 0 ; ----------------------- while w0 != 0
	bne	.L4 ;branch if not equal
	ldr	w0, [x29, 44] w0 = b_44
	ldp	x29, x30, [sp], 48
	ret
	.size	func1, .-func1
	.align	2
	.global	func2
	.type	func2, %function
func2:
	sub	sp, sp, #16 ;allocate stackspace
	str	w0, [sp, 12] c_12 = w0
	ldr	w0, [sp, 12] w0 = c_12
	add	w0, w0, 3 ; w0 = w0 + 3
	add	sp, sp, 16 ;clean and return
	ret
	.size	func2, .-func2
	.section	.rodata
	.align	3
.LC0:
	.string	"Result: %ld\n"
	.text
	.align	2
	.global	main
	.type	main, %function
main:
	;init stuff
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	w0, [x29, 28]
	str	x1, [x29, 16]
	ldr	x0, [x29, 16]

	;take arg
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi

	;call func1
	bl	func1

	;print result
	str	w0, [x29, 44]
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	ldr	w1, [x29, 44]
	bl	printf

	;return
	nop
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
