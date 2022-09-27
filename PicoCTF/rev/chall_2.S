	.arch armv8-a
	.file	"chall_2.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1:
	sub	sp, sp, #32 ; allocate stack space
	str	w0, [sp, 12] ; a_12 = arg (3848786505)
	str	wzr, [sp, 24] ; b_24 = 0
	str	wzr, [sp, 28] ; c_28 = 0
	b	.L2
.L3:
	ldr	w0, [sp, 24] w0 = b_24 = 0
	add	w0, w0, 3 w0 = w0 + 3 = 3
	str	w0, [sp, 24] b_24 = 3 ; w0 = b_24 = 4 bytes
	ldr	w0, [sp, 28] w0 = c_28 = 0
	add	w0, w0, 1 ; w0 = w0 +1 = 1
	str	w0, [sp, 28] c_28 = 1 ;keeps going downwards
.L2:
	ldr	w1, [sp, 28] ; w1 = c_28 = 0
	ldr	w0, [sp, 12] ; w0 = a_12 = arg
	cmp	w1, w0 ; w1 < w0 jmp to L3 ; while loop
	bcc	.L3
	ldr	w0, [sp, 24]
	add	sp, sp, 32
	ret
	.size	func1, .-func1
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

	;run func
	bl	func1
	
	;print result
	str	w0, [x29, 44]
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	ldr	w1, [x29, 44]
	bl	printf
	nop
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
