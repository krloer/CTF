from pwn import *

BINARY = ""
ARCH = 32

exe = ELF(f"./{BINARY}")
context.binary = exe

p = process(f"./{BINARY}")

####### Fill in program flow to reach overflow here:
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
#######

p.sendline(cyclic(1000))

p.wait()
core = p.corefile
if ARCH == 32:
    stack = core.esp
elif ARCH == 64:
    stack = core.rsp

log.info(f"{hex(stack)=}")
pattern = core.read(stack, 8)
rip_offset = cyclic_find(pattern)

if ARCH == 32: 
    rip_offset -= 4
log.success(f"{rip_offset=}")