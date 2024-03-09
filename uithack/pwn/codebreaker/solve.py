from pwn import *

# p = process("./codebreaker")
p = remote("uithack.td.org.uit.no", 9001)

p.recvuntil(b"shows: ")
seed = p.recvline().strip().decode()
print(seed)

s = process("./a.out", ["a.out", seed])
numbers = s.recvline().strip()
print(numbers)
s.close()

p.recvuntil(b"Your guess: ")
p.sendline(numbers)

p.interactive()

