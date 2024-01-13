from pwn import *

p = process("./a.out")
gdb.attach(p)

p.recvuntil(b"goes:")
p.interactive()
