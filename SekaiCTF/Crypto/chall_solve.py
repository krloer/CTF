import os
import random
import time

rand_nums = []

def encode_one():
    while len(rand_nums) != 8:
        tmp = int.from_bytes(os.urandom(1), "big") # numbers 1 through 7
        if tmp not in rand_nums:
            rand_nums.append(tmp)

    print(rand_nums)
    u = [s for s in sorted(zip(rand_nums, range(len(rand_nums))))]
    print(u)

    message = "Nice"
    res = ''
    for i in u:
        for j in range(i[1], len(message), len(rand_nums)):
            res += message[j]

    return res

res1 = encode_one()
print(res1)
message = res1.encode()

def encode_two():
    now = str(time.time()).encode('utf-8')
    now = now + "".join("0" for _ in range(len(now), 18)).encode('utf-8') #rounds to eight decimal places
    now = b'1664617736.7016640'
    print(now)

    random.seed(now)
    key = [random.randrange(256) for _ in message]

    res2 = [m ^ k for (m,k) in zip(message + now, key + [0x42]*len(now))]

    with open("test.enc", "wb") as f:
        f.write(bytes(res2))
    f.close()

encode_two()
print("decoding:")

def decode_second(now):
    # need correct time for now (in bytes)
    enc = ""
    with open("test.enc", "rb") as f: # length of flag is 43
        enc = f.read()
    f.close()

    random.seed(now)
    key = [random.randrange(256) for _ in enc]

    dec = [enc ^ k for (enc,k) in zip(enc, key + [0x42]*len(now))]
    res = ""
    for i in range(len(key)-len(now)):
        res += chr(dec[i])
    return res

def decode_first():
    return

now = b"1664617736.7016640"
decode1 = decode_second(now)
print(decode1)

# decoded = decode_first(decode1)
# print(decoded())
