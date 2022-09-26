	.arch armv8-a
	.file	"chall_1.c"
	.text
	.align	2
	.global	func
	.type	func, %function
func:
	sub	sp, sp, #32 ; allocate stack space (stack moves down towards heap)
	str	w0, [sp, 12] ; a_12 = arg1
	mov	w0, 85 ; w0 = 85
	str	w0, [sp, 16] ; b_16 = w0 (85)
	mov	w0, 6 ; w0 = 6
	str	w0, [sp, 20] ; c_20 = w0 (6)
	mov	w0, 3 ; w0 = 3
	str	w0, [sp, 24] ; d_24 = w0 (3)
	ldr	w0, [sp, 20] ; w0 = c_20 = 6
	ldr	w1, [sp, 16] ; w1 = b_16 = 85
	lsl	w0, w1, w0 ; w1 left shift * w0, store in w0 ( w0 = 85 *2⁶)
	str	w0, [sp, 28] ; e_28 = w0 = 5440 
	ldr	w1, [sp, 28] ; w1 = e_28 = 5440
	ldr	w0, [sp, 24] ; w0 = d_24 = 3
	sdiv	w0, w1, w0 ; w0 = w1 / w0 = 5440 / 3 = 1813
	str	w0, [sp, 28] ; e_28 = w0 = 1813
	ldr	w1, [sp, 28] ; w1 = e_28 = 1813
	ldr	w0, [sp, 12] ; w0 = a_12 = arg1
	sub	w0, w1, w0 ; w0 = 1813 - arg1
	str	w0, [sp, 28] ; e_28 = w0 = 1813 - arg1
	ldr	w0, [sp, 28] ; w0 = e_28 = 1813 - arg1
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
.LC0:
	.string	"You win!"
	.align	3
.LC1:
	.string	"You Lose :("
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

	; load arg
	ldr	x0, [x29, 16]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	str	w0, [x29, 44] ;store
	ldr	w0, [x29, 44] ; then load...
	bl	func ; func affects w0

	cmp	w0, 0 ; w0 == 0 ? (1813 - arg) == 0 ?
	bne	.L4 ; branch if not equal, jump to .L4
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	puts ; .LC0 you win
	b	.L6
.L4:
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	puts ; .LC1 = you lose
.L6:
	; cleanup
	nop
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
