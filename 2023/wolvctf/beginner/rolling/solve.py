enc = "983f687f03f884a9983f687e0ff2afbc983f687d03a891bd983f687c2bf68990983f687b04e9c0a9983f687a2be8c4a6983f687910c482ff983f687818f7afb6983f687744ee8290983f687644ec9e90983f687517e989bf983f687400ab8dcf"

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

# for i in range(0, 48, 4):
#     index = long_to_bytes(i // 4)
#     index = b'\x00' * (4 - len(index)) + index 
#     print(index)

key1 = strxor(long_to_bytes(0x983f687f), b"\x00\x00\x00\00").hex()

# first half of key = 983f687f

# first part of flag encoded: 03f884a9
# "wctf" ^key = 03f884a9
# key = wctf ^ 03f884a9
key2 = strxor("wctf".encode(),long_to_bytes(0x03f884a9))
print(key2.hex())

parts = ["0x" + enc[i:i+8] for i in range(0, len(enc), 8)]
flag = ""

for i in range(1, len(parts), 2):
    flag_part = long_to_bytes(int(parts[i], 16))
    padded = b"\x00" * (4 - len(flag_part)) + flag_part
    flag += strxor(padded, key2).decode()

print(flag)
