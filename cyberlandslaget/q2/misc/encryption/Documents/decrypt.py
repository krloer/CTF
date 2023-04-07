from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("important_email.eml.enc", "r") as f:
    for line in f.readlines():
        mac_in,iv_in,enc_in,aes_in = line.split(":")
        try:
            iv = b64decode(iv_in)
            ciphertext = b64decode(enc_in)
            key = b64decode(aes_in)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            print(plaintext)
        except (ValueError, KeyError):
            print("ERROR!")