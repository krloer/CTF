from pwn import *

package = "a" * 32
encoded  = "51466d4e5f575538195551416e4f5300413f1b5008684d5504384157046e4959"

sending = "a" * 49968
r = remote('mercury.picoctf.net', 64260)

r.recvuntil(b"What data would you like to encrypt?")
r.send(sending.encode())
r.send(b"\n")
r.recvuntil(b"Here ya go!")
r.recvline()
r.recvuntil(b"What data would you like to encrypt?")
r.send(package.encode())
r.send(b"\n")
r.recvuntil(b"Here ya go!")
r.recvline()
output = r.recvline().decode().rstrip("\n")

arr=output
arr = [arr[i:i+2] for i in range(0, len(arr), 2)]

key = list(map(lambda p, k: int(p, base=16) ^ k, arr, package.encode())) #gets key

encoded = [encoded[i:i+2] for i in range(0, len(encoded), 2)]
decoded = list(map(lambda p, k: chr(int(p, base=16) ^ k), encoded, key))

flag1 = "picoCTF{"
flag2 = "}"
print(flag1 + "".join(decoded) + flag2)

# picoCTF{3a16944dad432717ccc3945d3d96421a}
