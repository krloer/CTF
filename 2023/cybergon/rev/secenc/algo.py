# Source Generated with Decompyle++
# File: algorithm.pyc (Python 3.11)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

import binascii

data = b"secret"
passphrase = b'UniquePassphrase'
salt = b'FixedUniqueSalt123'
kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt, iterations = 100000, backend = default_backend())
key = kdf.derive(passphrase)
print(binascii.hexlify(key))

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(data) + encryptor.finalize()
output = iv + encrypted_data
print(output)
print(iv)
print(output[:16])