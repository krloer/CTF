from pwn import *

r = remote("lac.tf", 31111)

p = int(r.recvline())
q = int(r.recvline())

n=p*q
print(p)
print(q)
print(str(len(str(p))) + " " + str(len(str(p))))
print(n)
print("__________________________")

print("high and low:")
high = max(p,q)
low = min(p,q)
print(high)
print(low)
# n / limit == min(p,q)
# n % p == n % q == 0
print("__________________________")

firstmod = high-1
secondmod = low-2

r.recvuntil(b">>")
r.sendline(b"1")
r.recvuntil(b"modulus here:")
r.sendline(str(firstmod).encode())
res1 = int(r.recvline().decode().strip())

r.recvuntil(b">>")
r.sendline(b"1")
r.recvuntil(b"modulus here:")
r.sendline(str(secondmod).encode())
res2 = int(r.recvline().decode().strip())

print("modulus results:")
print(res1)
print(res2)
print("_________________________")

apos = []
bpos = []
pos = []

for i in range(res1, n*2*3*5, firstmod):
    apos.append(i)

for i in range(res2, n*2*3*5, secondmod):
    bpos.append(i)

pos = [x for x in apos if x in bpos] 

print(pos)
print(len(pos))

r.interactive()
