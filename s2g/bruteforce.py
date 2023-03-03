from Crypto.Cipher import AES
from Crypto.Util.number import *
from base64 import b64decode, b64encode

real_iv = b"1234567890123456"
enc = b64decode("+vrXfpBAA9wGyxmX2pZksxLt+hFnJFwUgLJJGghdLwueqPibuOl97qYH2U5Q19De")

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

for score in range(112,5555):
    key = (str(score).rjust(4, "0"))*4
    cipher = AES.new(key.encode("utf8"), AES.MODE_CBC, real_iv)
    # print(cipher.decrypt(enc.encode("utf8")))
    try: 
        out = cipher.decrypt(enc)
        if b"S2G" in out:
            print(out)
    except:
        continue



# IV = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6])

# BLOCK_SIZE = 16
# pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
# unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# def encrypt(plain_text, key):
#     plain_text = pad(plain_text)
#     cipher = AES.new(key, AES.MODE_CBC, IV)
#     return b64encode(cipher.encrypt(plain_text))


# def decrypt(cipher_text, key):
#     cipher_text = b64decode(cipher_text)
#     cipher = AES.new(key, AES.MODE_CBC, IV)
#     return unpad(cipher.decrypt(cipher_text))

# if __name__ == '__main__':
#     key = "AnyRandomInsecure256bitLongKeyXX".encode()

#     encrypted = encrypt("data", key)
#     decrypted = decrypt(encrypted, key)
#     print(f"{encrypted} <-> {decrypted}")