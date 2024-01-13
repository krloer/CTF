import random

def shuffle_under_seed(ls, seed):
  # Shuffle the list ls using the seed `seed`
  random.seed(seed)
  random.shuffle(ls)
  return ls

def unshuffle_list(shuffled_ls, seed):
  n = len(shuffled_ls)
  # Perm is [1, 2, ..., n]
  perm = [i for i in range(1, n + 1)]
  # Apply sigma to perm
  shuffled_perm = shuffle_under_seed(perm, seed)
  # Zip and unshuffle
  zipped_ls = list(zip(shuffled_ls, shuffled_perm))
  zipped_ls.sort(key=lambda x: x[1])
  return [a for (a, b) in zipped_ls]

start = list(range(10))
ls = shuffle_under_seed(start, "9796e0edef")
print(ls)
stop = unshuffle_list(ls, "9796e0edef")
print(stop)