flag= list("UiTHack{")
for i in range(33):
    flag.append("")
flag.append("}")
enc = [0x3c, 0x3d, 0x1c, 0x29, 0x02, 0x08, 0x59, 0x06, 0x4f, 0x11, 0x5e, 0x42, 0x42, 0x47, 0x10, 0x11, 0x43, 0x41, 0x47, 0x68, 0x6e, 0x04, 0x6a, 0x3e, 0x0f, 0x31, 0x6b, 0x58, 0x5d, 0x54, 0x0b, 0x31, 0x33, 0x58, 0x5a, 0x09, 0x12, 0x41, 0x53, 0x54, 0x4e, 0x7d]

for i in range(2, len(enc)):
    flag[-i] = chr(ord(flag[-i+1]) ^ enc[-i])

print("".join(flag))