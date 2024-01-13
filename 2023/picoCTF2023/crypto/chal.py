from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

plaintext = "".join(choice(ascii_letters + digits) for _ in range(16))
p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# d * e % phi = 1

ciphertext = pow(bytes_to_long(plaintext.encode()), e, n) # m^e % n

print(f"{ciphertext = }")
print(f"{d = }")

# c = m^e % n
# m = c^d % n

print("vainglory?")
user_input = input("> ").strip()

if user_input == plaintext:
    print("Conquered!")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Hubris!")
