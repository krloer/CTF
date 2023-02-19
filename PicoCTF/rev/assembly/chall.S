	.arch armv8-a
	.file	"chall.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1:
	sub	sp, sp, #16 ;allocate 16 bytes
	str	w0, [sp, 12] ; sp+12 = a = w0
	str	w1, [sp, 8] ; sp + 8 = b = w1
	ldr	w1, [sp, 12] ; w1 = a
	ldr	w0, [sp, 8] ; w0 = b
	cmp	w1, w0 ; compare a og b
	bls	.L2 ; hvis a <= b, jump to .L2
	ldr	w0, [sp, 12] ; w0 = a
	b	.L3 ; jump to .L3
.L2:
	ldr	w0, [sp, 8] ; w0 = b
.L3:
	add	sp, sp, 16
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
	;init things ?
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	x19, [sp, 16]
	str	w0, [x29, 44]
	str	x1, [x29, 32]

	;read input 1 ; 1830628817
	ldr	x0, [x29, 32]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	mov	w19, w0 ; move w0 to w19 (w0 = lowest 4 bytes in x0)

	;read input 2 ; 1765227561
	ldr	x0, [x29, 32]
	add	x0, x0, 16
	ldr	x0, [x0]
	bl	atoi
	mov	w1, w0
	mov	w0, w19

	;func1()
	bl	func1
	mov	w1, w0

	;prepare format strings
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0

	;printf()
	bl	printf

	;cleanup?
	mov	w0, 0
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
