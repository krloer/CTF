from pwn import *

p = remote("10.212.138.23", 54790)

p.recvline(b"(y/n)")
p.sendline(b"y")

p.recvuntil(b":")
word = p.recvline().strip()
p.sendline(word)
for _ in range(49):
    word = p.recvline().split(b":")[-1][1:].strip()
    p.sendline(word)

p.interactive()
