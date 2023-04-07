from hashlib import * 
import string
import random

c = "0123456789-"
flippy = lambda x: bytes.fromhex((m:=x.encode().hex())[1::2]+m[::2])

ALPHABET = string.ascii_letters
check3 = lambda x,y: exit(-3) if not all(f(flippy(x)).hexdigest().startswith(g) for f,g in zip([md5,sha1,sha256,sha384,sha256], y.split("-"))) else None

while True:
    name = ''.join(random.choice(ALPHABET) for i in range(16))
    first = md5(flippy(name)).hexdigest()[:5]
    if all(x in c for x in first):
        second = sha1(flippy(name)).hexdigest()[:5]
        if all(x in c for x in second):
            third = sha256(flippy(name)).hexdigest()[:5]
            if all(x in c for x in third):
                fourth = sha384(flippy(name)).hexdigest()[:5]
                if all(x in c for x in fourth):
                    fifth = sha256(flippy(name)).hexdigest()[:5]
                    if all(x in c for x in fifth):
                        print("md5: ", md5(flippy(name)).hexdigest())
                        print("sha1: ", sha1(flippy(name)).hexdigest())
                        print("sha256: ", sha256(flippy(name)).hexdigest())
                        print("sha384: ", sha384(flippy(name)).hexdigest())
                        print("sha256: ", sha256(flippy(name)).hexdigest())
                        print("=====================")
                        print(name)
                        print(str(first) + "-" + str(second) + "-" + str(third) + "-" + str(fourth) + "-" + str(fifth))
                        break
