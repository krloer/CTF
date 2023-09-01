known = b"S2G{"

encrypted = []
with open("output.txt", "r") as file:
    for line in file.readlines():
        encrypted.append(bytes.fromhex(line.strip()))

def xor(message, key):
    return bytes(m ^ c for m, c in zip(message, key))


j = 0
for enc in encrypted:
    for i in range(len(enc)-4):
        key_part = xor(known, enc[i:i+4])

        decrypted = []
        for enc in encrypted:
            dec_part = xor(key_part, enc[i:i+4])
            enc = enc.replace(enc[i:i+4], dec_part)
            decrypted.append(enc)
                
        with open(f"tmp/test{j}_{i}.txt", "w") as file:
            for dec in decrypted:
                line = "".join([chr(c) for c in list(dec)])
                file.write(str(line)+"\n\n")
    j += 1

