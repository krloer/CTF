asm1:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
					; 0x2e0
	<+3>:	cmp    DWORD PTR [ebp+0x8],0x71c ; in > 1820?
	<+10>:	jg     0x512 <asm1+37> ; jump if greater
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x6cf ; in != 1743?
	<+19>:	jne    0x50a <asm1+29> ; jump if not equal
	<+21>:	mov    eax,DWORD PTR [ebp+0x8] ; eax = 0x2e0
	<+24>:	add    eax,0x3 ; eax += 0x3
	<+27>:	jmp    0x529 <asm1+60> ; end
	<+29>:	mov    eax,DWORD PTR [ebp+0x8] ; eax = 0x20e
	<+32>:	sub    eax,0x3 ; eax -= 0x3
	<+35>:	jmp    0x529 <asm1+60> ; end
	<+37>:	cmp    DWORD PTR [ebp+0x8],0x8be ; 0x2e0 != 0x8be ?
	<+44>:	jne    0x523 <asm1+54> ; jump if not equal
	<+46>:	mov    eax,DWORD PTR [ebp+0x8] ; eax = 0x2e0
	<+49>:	sub    eax,0x3 ; eax -= 0x3
	<+52>:	jmp    0x529 <asm1+60> ; end
	<+54>:	mov    eax,DWORD PTR [ebp+0x8]
	<+57>:	add    eax,0x3 ; eax += 0x3
	<+60>:	pop    ebp
	<+61>:	ret    

