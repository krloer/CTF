from secret import messages
import re
import os

assert all(len(msg) <= 256 for msg in messages), 'The messages are too long.'
assert any(re.search(b'S2G{.*}', msg) for msg in messages), 'The flag is missing.'

def encrypt(message, key=os.urandom(256)):
    return bytes(m ^ c for m, c in zip(message, key))

for msg in messages:
    print(encrypt(msg).hex())
