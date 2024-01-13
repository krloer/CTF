def hex_to_ascii(hex):
    return bytearray.fromhex(hex).decode()

enc = "cdd3c8cee2d9d6dbc8dbd0d5cec6cad0d7cfccd9dac6c8d9ccc6ccc8dae0c6dbd6c6c9d9dcdbccc6cdd6d9cacce4"

plaintext_bytes = bytes.fromhex(enc)


for i in range(256):
    flag = ""
    for number in plaintext_bytes:
        # hex_number = number.decode()
        real = (number - i) % 256
        flag += chr(real)
    if "flag{" in flag:
        print(flag) 

# print(plaintext_bytes)

# print(hex_to_ascii(enc))