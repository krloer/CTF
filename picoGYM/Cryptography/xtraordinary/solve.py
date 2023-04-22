random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

out = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"
benc = bytes.fromhex(out)

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

for i in range(2):
    for j in range(2):
        for k in range(2):
            for l in range(2):
                for m in range(2):
                    enc = benc
                    if i == 1:
                        enc = encrypt(enc, random_strs[0])
                    if j == 1:
                        enc = encrypt(enc, random_strs[1])
                    if k == 1:
                        enc = encrypt(enc, random_strs[2])
                    if l == 1:
                        enc = encrypt(enc, random_strs[3])
                    if m == 1:
                        enc = encrypt(enc, random_strs[4])
                    start = "picoCTF"
                    key = encrypt(enc[:len(start)], start.encode())
                    poss = encrypt(enc,key)
                    if b"}" in poss and b"picoCTF{" in poss:
                        print(poss)
                