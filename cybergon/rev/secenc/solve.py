from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

import binascii

with open("./flag.enc", 'rb') as infile:
    data = infile.read()

passphrase = b'UniquePassphrase'
salt = b'FixedUniqueSalt123'
kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt, iterations = 100000, backend = default_backend())
key = kdf.derive(passphrase)
print(binascii.hexlify(key))

iv = data[:16]

cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
decryptor = cipher.decryptor()
decrypted_data = decryptor.update(data) + decryptor.finalize()
print(decrypted_data)
