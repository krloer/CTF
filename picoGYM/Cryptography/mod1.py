import string

enc = [350, 63, 353, 198, 114, 369, 346, 184, 202, 322, 94, 235, 114, 110, 185, 188, 225, 212, 366, 374, 261, 213]
ALPHABET = string.ascii_lowercase + string.digits + "_"
flag = "picoCTF{"

for c in enc:
    flag += ALPHABET[c%37]

print(flag + "}")