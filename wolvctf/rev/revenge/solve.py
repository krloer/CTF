from Crypto.Util.number import long_to_bytes

enc = ""
with open("flag.txt.enc", "rb") as file:
    enc = file.read()

flag = b""
for i in range(0, len(enc), 4):
    part = int(enc[i:i+4][::-1].hex(), 16)
    dec = (part >> 0xd | part << 0x13) & 0xffffffff
    flag += long_to_bytes(dec)[::-1]

print(flag.decode())