import string
import base64
enc = "OS1QYj9VaEolaDgTSTXxSWj5Uj5JNVwRUT4vX290L1ondF1z"
shifted = ""

for c in enc:
    if c in string.ascii_letters:
        base = 0
        if c in string.ascii_lowercase:
            base = ord("a")
        else:
            base = ord("A")

        offset = (ord(c) - base - 25) % 26
        if offset < 0:
            offset += 26
        shifted += chr(base+offset)
    else:
        shifted += c

print(shifted)

dec1 = base64.b64decode(shifted)

print(dec1)

reversed = dec1[::-1]
print(reversed)

dec = base64.b64decode(reversed)
print(dec)
