import string

enc = [104, 372, 110, 436, 262, 173, 354, 393, 351, 297, 241, 86, 262, 359, 256, 441, 124, 154, 165, 165, 219, 288, 42]
ALPHABET = "?" + string.ascii_lowercase + string.digits + "_"
flag = "picoCTF{"

n = 41

for c in enc:
    r = c % n
    flag += ALPHABET[pow(r, -1, n)]

print(flag + "}")