#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def gcd(a, b):
    while(a != 0):
        r = b%a
        b,a = a,r
    return b

def getAnnoyingPrime(nbits, e):
	while True:
		p = getPrime(nbits)
		q = getPrime(nbits)
		b = (p-1)*(q-1)
		if (gcd(e,b) == 1 and p*q == 57996511214023134147551927572747727074259762800050285360155793732008227782157):
			return p,q


nbits = 128
e = 17


p,q = getAnnoyingPrime(nbits, e)
# p = getAnnoyingPrime(nbits, e)
# q = getAnnoyingPrime(nbits, e)
# b = (p-1)(q-1)

flag = b"dice{???????????????????????}"

N = p * q
cipher = pow(bytes_to_long(flag), e, N)
# flag ** e mod N

print(f"N = {N}")
print(f"e = {e}")
print(f"cipher = {cipher}")

#      N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
# e = 17
# # cipher = 19441066986971115501070184268860318480501957407683654861466353590162062492971

# pq = 57996511214023134147551927572747727074259762800050285360155793732008227782157
# offentlig = n,e = 57996511214023134147551927572747727074259762800050285360155793732008227782157, 17
# privat = n,d = 57996511214023134147551927572747727074259762800050285360155793732008227782157, d

# # n,e
# # n,d

# # p og q primtall
# # n = pq
# # b = (p-1)(q-1)
# # gcd(e, b) = 1

# # e * d - b * y = 1

# M = C**d mod N
# M = cipher