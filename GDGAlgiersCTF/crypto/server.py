#!/usr/bin/env python3
# Crypto challenge of eXORciste
import os 
from flag import FLAG
import random

def xor(message, key):
    return ''.join([chr(m^k) for m,k in zip(message, key)] )
    


def generate_key(length):
    random_seed = os.urandom(16) # 16 random bytes
    key = random_seed * (length //16) + random_seed[:(length % 16)] # random_seed*8 (assuming input length 128)
    return key 



def main():
    print("Hello Stranger, send me your secret and I will make sure to roll it up")
    while True:
        message = input('>> ').encode() #b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        if len(message)<20:
            print('That is not a secret man!')
            exit()
        key = generate_key(len(message)) # 128
        offset = random.randint(0, len(message)) # places flag at random location in message
        cipher = xor(message[:offset]+FLAG+message[offset:], key) #random_seed*8 xor message with flag in it
        print("> "+ cipher.encode().hex())


if __name__ == "__main__":
    main()


