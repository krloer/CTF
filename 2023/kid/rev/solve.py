import time
import random

def unroll(dough):
    print([((int("0x" + x, 16) + 128)%256) for x in dough])
    return [((int("0x" + x, 16) + 128)%256) for x in dough]

def unmix(ingredients):
    print([chr(x ^ 0x24) for x in ingredients])
    return [chr(x ^ 0x24) for x in ingredients]

def heat_ingredients(ingredients):
    return "".join([ingredients[i] for i in range(len(ingredients)-1,-1,-1)])
    #reverses and joins list

def shuffle_under_seed(ls, seed): # needed for unshuffling
  random.seed(seed)
  random.shuffle(ls)
  return ls

def unshuffle_list(shuffled_ls, seed): # Thank you https://crypto.stackexchange.com/questions/78309/how-to-get-the-original-list-back-given-a-shuffled-list-and-seed
  n = len(shuffled_ls)
  # Perm is [1, 2, ..., n]
  perm = [i for i in range(1, n + 1)]
  # Apply sigma to perm
  shuffled_perm = shuffle_under_seed(perm, seed)
  # Zip and unshuffle
  zipped_ls = list(zip(shuffled_ls, shuffled_perm))
  zipped_ls.sort(key=lambda x: x[1])
  return [a for (a, b) in zipped_ls]

encoded = "90edd1c3dfc2cacacae09596fb97fbc6cfd99097efc6c7fb"

work = []
#unbake:
for i in range(0, len(encoded), 2):
    work.append(encoded[i:i+2])
print(work)

work1 = unshuffle_list(work, "9796e0edef")
work2 = unroll(work1)
work3 = unmix(work2)
print(heat_ingredients(work3))