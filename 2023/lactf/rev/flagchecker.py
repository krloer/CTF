
inp = list("X"*0x26)
inp[0] = "l"
inp[1] = "a"
inp[2] = "c"
inp[3] = "t"
inp[4] = "f"
inp[5] = "{"

# inp[0x14] ^ inp[2] * 7 ^ (inp[1] ^ -1) + 0xd == 0x2f

print(inp[0x14])


(pbVar3[0x22] ^ pbVar3[0x17] * 7 ^ (pbVar3[0x24] ^ -1) + 0xd) & 0xFF = -0x4a


inp[0x25] = "}"

exit(0)

print("".join(inp))
inp[0x22] ^ inp[0x17] * 7 ^ (inp[0x24] ^ -1) + 0xd == -0x4a 
inp[0x25] ^ inp[10] * 7 ^ (inp[0x15] ^ -1) + 0xd == -0x21 
inp[0x18] ^ inp[0x17] * 7 ^ (inp[0x13] ^ -1) + 0xd == -0x33 
inp[0x19] ^ inp[0xd] * 7 ^ (inp[0x17] ^ -1) + 0xd == -0x70 
inp[6] ^ inp[0x1b] * 7 ^ (inp[0x19] ^ -1) + 0xd == -0x76 
inp[4] ^ inp[0x20] * 7 ^ (inp[0x16] ^ -1) + 0xd == -0x1d 
inp[0x19] ^ inp[0x13] * 7 ^ (inp[1] ^ -1) + 0xd == 0x6b 
inp[0x16] ^ inp[7] * 7 ^ (inp[0x1d] ^ -1) + 0xd == 0x55 
inp[0xf] ^ inp[10] * 7 ^ (inp[0x14] ^ -1) + 0xd == -0x44 
inp[0x1d] ^ inp[0x10] * 7 ^ (inp[0xc] ^ -1) + 0xd == 0x58 
inp[0x23] ^ inp[4] * 7 ^ (inp[0x21] ^ -1) + 0xd == 0x54 
inp[0x24] ^ inp[2] * 7 ^ (inp[4] ^ -1) + 0xd == 0x67 
inp[0x1a] ^ inp[3] * 7 ^ (inp[1] ^ -1) + 0xd == -0x28 
inp[0xc] ^ inp[6] * 7 ^ (inp[0x12] ^ -1) + 0xd == -0x5b 
inp[0xc] ^ inp[0x1c] * 7 ^ (inp[0x24] ^ -1) + 0xd == -0x69 
inp[0x14] ^ inp[0] * 7 ^ (inp[0x15] ^ -1) + 0xd == 0x65 
inp[0x1b] ^ inp[0x24] * 7 ^ (inp[0xe] ^ -1) + 0xd == -8 
inp[0x23] ^ inp[2] * 7 ^ (inp[0x13] ^ -1) + 0xd == 0x2c 
inp[0xd] ^ inp[0xb] * 7 ^ (inp[0x21] ^ -1) + 0xd == -0xe 
inp[0x21] ^ inp[0xb] * 7 ^ (inp[3] ^ -1) + 0xd == -0x15 
inp[0x1f] ^ inp[0x25] * 7 ^ (inp[0x1d] ^ -1) + 0xd == -8 
inp[1] ^ inp[0x21] * 7 ^ (inp[0x1f] ^ -1) + 0xd == 0x21 
inp[0x22] ^ inp[0x16] * 7 ^ (inp[0x23] ^ -1) + 0xd == 0x54 
inp[0x24] ^ inp[0x10] * 7 ^ (inp[4] ^ -1) + 0xd == 0x4b 
inp[8] ^ inp[3] * 7 ^ (inp[10] ^ -1) + 0xd == -0x2a 
inp[0x14] ^ inp[5] * 7 ^ (inp[0xc] ^ -1) + 0xd == -0x3f 
inp[0x1c] ^ inp[0x22] * 7 ^ (inp[0x10] ^ -1) + 0xd == -0x2e 
inp[3] ^ inp[0x23] * 7 ^ (inp[9] ^ -1) + 0xd == -0x33 
inp[0x1b] ^ inp[0x16] * 7 ^ (inp[2] ^ -1) + 0xd == 0x2e 
inp[0x1b] ^ inp[0x12] * 7 ^ (inp[9] ^ -1) + 0xd == 0x36 
inp[3] ^ inp[0x1d] * 7 ^ (inp[0x16] ^ -1) + 0xd == 0x20 
inp[0x18] ^ inp[4] * 7 ^ (inp[0xd] ^ -1) + 0xd == 99 
inp[0x16] ^ inp[0x10] * 7 ^ (inp[0xd] ^ -1) + 0xd == 0x6c 
inp[0xc] ^ inp[8] * 7 ^ (inp[0x1e] ^ -1) + 0xd == 0x75 
inp[0x19] ^ inp[0x1b] * 7 ^ (inp[0x23] ^ -1) + 0xd == -0x6e 
inp[0x10] ^ inp[10] * 7 ^ (inp[0xe] ^ -1) + 0xd == -6 
inp[0x15] ^ inp[0x19] * 7 ^ (inp[0xc] ^ -1) + 0xd == -0x3d 
inp[0x1a] ^ inp[10] * 7 ^ (inp[0x1e] ^ -1) + 0xd == -0x35 
inp[0x14] ^ inp[2] * 7 ^ (inp[1] ^ -1) + 0xd == 0x2f 
inp[0x22] ^ inp[0xc] * 7 ^ (inp[0x1b] ^ -1) + 0xd == 0x79 
inp[0x13] ^ inp[0x22] * 7 ^ (inp[0x14] ^ -1) + 0xd == -10 
inp[0x19] ^ inp[0x16] * 7 ^ (inp[0xe] ^ -1) + 0xd == 0x3d 
inp[0x13] ^ inp[0x1c] * 7 ^ (inp[0x25] ^ -1) + 0xd == -0x43 
inp[0x18] ^ inp[9] * 7 ^ (inp[0x11] ^ -1) + 0xd == -0x47

print("".join(inp))