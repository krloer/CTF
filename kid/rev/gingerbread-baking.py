import time
import random

FLAG = "KID23{redacted}"

def heat_ingredients(ingredients):
    print("Preparing the ingredients...")
    time.sleep(1)
    print("".join([ingredients[i] for i in range(len(ingredients)-1,-1,-1)]))
    return "".join([ingredients[i] for i in range(len(ingredients)-1,-1,-1)])
    # snur stringen

def mix_into_dough(ingredients):
    print("Mixing the ingredients into dough...")
    time.sleep(1)
    print([ord(x) ^ 0x24 for x in ingredients])
    return [ord(x) ^ 0x24 for x in ingredients]
    # converts to ascii and XORs with 36

def roll_dough(dough):
    print("Rolling the cookie dough...")
    time.sleep(1)
    print([hex((x - 128)%256)[2:] for x in dough])
    return [hex((x - 128)%256)[2:] for x in dough]

def cut_into_shapes(dough):
    print("Shaping the cookie dough...")
    time.sleep(1)
    random.seed("".join(dough[-5:])) # "".join(dough[-5:])
    random.shuffle(dough)
    print(dough)
    return dough

def bake(dough):
    print("Baking the cookie...")
    time.sleep(1)
    cookie = ""
    for d in dough:
        cookie += d
    print(cookie)
    return cookie

if __name__ == "__main__":
    cookie = cut_into_shapes(roll_dough(mix_into_dough(heat_ingredients(FLAG))))
    print()
    print("Here's your freshly baked gingebread cookie!")
    print(cookie)
