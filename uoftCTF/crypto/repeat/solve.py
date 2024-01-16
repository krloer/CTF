def xor(message, key):
    return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])

enc = bytes.fromhex("982a9290d6d4bf88957586bbdcda8681de33c796c691bb9fde1a83d582c886988375838aead0e8c7dc2bc3d7cd97a4")
key = xor(b"uoftctf{", enc)
flag = xor(enc, key)

print(flag.decode())

