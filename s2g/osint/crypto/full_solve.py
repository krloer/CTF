def xor(message, key):
    return bytes(m ^ c for m, c in zip(message, key))

encrypted = []
with open("output.txt", "r") as file:
    for line in file.readlines():
        encrypted.append(bytes.fromhex(line.strip()))


key_part = xor(encrypted[3][0:3], b"S2G")
key_part += bytes([encrypted[6][3] ^ ord("h")])
key_part += bytes([encrypted[6][4] ^ ord("o")])
key_part += bytes([encrypted[6][5] ^ ord("n")])
key_part += bytes([encrypted[6][6] ^ ord(" ")])
key_part += bytes([encrypted[8][7] ^ ord("g")])
key_part += bytes([encrypted[7][8] ^ ord("u")])
key_part += bytes([encrypted[7][9] ^ ord("s")])
key_part += bytes([encrypted[7][10] ^ ord("e")])
key_part += bytes([encrypted[2][11] ^ ord("e")])
key_part += bytes([encrypted[2][12] ^ ord("r")])
key_part += bytes([encrypted[2][13] ^ ord("e")])
key_part += bytes([encrypted[2][14] ^ ord(" ")])
key_part += bytes([encrypted[3][15] ^ ord("n")])
key_part += bytes([encrypted[3][16] ^ ord("n")])
key_part += bytes([encrypted[2][17] ^ ord("s")])
key_part += bytes([encrypted[2][18] ^ ord("e")])
key_part += bytes([encrypted[1][19] ^ ord("2")])
key_part += bytes([encrypted[1][20] ^ ord("G")])
key_part += bytes([encrypted[1][21] ^ ord("{")])
key_part += bytes([encrypted[11][22] ^ ord("g")])
key_part += bytes([encrypted[7][23] ^ ord("y")])
key_part += bytes([encrypted[9][24] ^ ord("f")])
key_part += bytes([encrypted[6][25] ^ ord("t")])
key_part += bytes([encrypted[11][26] ^ ord("g")])
key_part += bytes([encrypted[11][27] ^ ord("e")])
key_part += bytes([encrypted[11][28] ^ ord("t")])
key_part += bytes([encrypted[11][29] ^ ord("h")])
key_part += bytes([encrypted[11][30] ^ ord("e")])
key_part += bytes([encrypted[11][31] ^ ord("r")])
key_part += bytes([encrypted[5][32] ^ ord("s")])
key_part += bytes([encrypted[5][33] ^ ord(" ")])
key_part += bytes([encrypted[9][34] ^ ord("e")])
key_part += bytes([encrypted[4][35] ^ ord(" ")])
key_part += bytes([encrypted[3][36] ^ ord("t")])
key_part += bytes([encrypted[3][37] ^ ord(" ")])
key_part += bytes([encrypted[4][38] ^ ord("y")])
key_part += bytes([encrypted[9][39] ^ ord("e")])
key_part += bytes([encrypted[9][40] ^ ord("s")])
key_part += bytes([encrypted[9][41] ^ ord("s")])
key_part += bytes([encrypted[9][42] ^ ord("a")])
key_part += bytes([encrypted[9][43] ^ ord("g")])
key_part += bytes([encrypted[9][44] ^ ord("e")])
key_part += bytes([encrypted[9][45] ^ ord("s")])
key_part += bytes([encrypted[5][46] ^ ord("o")])
key_part += bytes([encrypted[5][47] ^ ord("s")])
key_part += bytes([encrypted[5][48] ^ ord("t")])
key_part += bytes([encrypted[5][49] ^ ord(" ")])
key_part += bytes([encrypted[5][50] ^ ord("g")])
key_part += bytes([encrypted[5][51] ^ ord("o")])
key_part += bytes([encrypted[5][52] ^ ord("t")])
key_part += bytes([encrypted[5][53] ^ ord(" ")])
key_part += bytes([encrypted[5][54] ^ ord("i")])
key_part += bytes([encrypted[5][55] ^ ord("t")])


progress = len(key_part)


# print(key_part[3])

decrypted = []
for enc in encrypted:
    dec_part = xor(key_part, enc[0:progress])
    enc = enc.replace(enc[0:progress], dec_part)
    decrypted.append(enc)
        
with open(f"solve.txt", "w") as file:
    for dec in decrypted:
        line = "".join([chr(c) for c in list(dec)])
        file.write(str(line)+"\n\n")

