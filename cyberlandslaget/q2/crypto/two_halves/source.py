from Crypto.Util.number import bytes_to_long, isPrime, getPrime
import random
import os
flag = open("flag.txt").read().strip().encode()


def generate_random_prime():
    while True:
        random.seed(os.urandom(1024))
        bits = [random.getrandbits(32) for _ in range(33)]
        random.getrandbits(364*32)
        bits += [random.getrandbits(32) for _ in range(32)]
        random.getrandbits(195*32)

        n = random.getrandbits(1024)
        if isPrime(n):
            break

    return bits, n


q = getPrime(1024)
bits, p = generate_random_prime()

n = p*q
e = 65537
ct = pow(bytes_to_long(flag), e, n)
print(f"bits={bits}")
print(f"n={n}")
print(f"ct={ct}")
