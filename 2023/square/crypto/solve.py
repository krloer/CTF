import itertools
import base64

b64_enc = 'LEs2fVVxNDMfNHEtcx80cB8nczQfJhVkDHI/Ew=='
enc = base64.b64decode(b64_enc)

def slide(ct, key):
    for i in range(len(ct)-len(key)+1):
        for j in range(len(key)):
            ct[i + j] ^= key[j]
    return ct

"""
for(int i = 0; i < flag_len - key_len + 1; i++) {
        for(int j = 0; j < key_len; j++) {
            flag[i + j] ^= key[j];
        }
    }
"""

key = [enc[0] ^ ord("f")]
key.append(enc[1] ^ key[0] ^ ord("l"))
key.append(enc[2] ^ key[1] ^ key[0] ^ ord("a"))
key.append(enc[3] ^ key[2] ^ key[1] ^ key[0] ^ ord("g"))
key.append(enc[4] ^ key[3] ^ key[2] ^ key[1] ^ key[0] ^ ord("{"))
key.append(enc[-1] ^ ord("}"))

flag = "".join([chr(c) for c in slide(list(enc), key)]).encode()
print(flag)
