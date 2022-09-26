#!/usr/bin/python3 -u
import os.path

KEY_FILE = "key"
KEY_LEN = 50000
FLAG_FILE = "flag"


def startup(key_location):
	flag = open(FLAG_FILE).read()
	kf = open(KEY_FILE, "rb").read()

	start = key_location
	stop = key_location + len(flag) # stop = 32

	key = kf[start:stop] # 0:32
	key_location = stop # key_location = 32

	result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key)) 
	print("This is the encrypted flag!\n{}\n".format("".join(result)))
	return key_location

def encrypt(key_location): #key_location = 32
	ui = input("What data would you like to encrypt? ").rstrip()
	if len(ui) == 0 or len(ui) > KEY_LEN: #check if ui is 0 or over 50000
		return -1

	start = key_location # 32
	stop = key_location + len(ui) #32 + 50000 = 50032

	kf = open(KEY_FILE, "rb").read()

	if stop >= KEY_LEN:
		stop = stop % KEY_LEN #50032 % 50000 = 32
		key = kf[start:] + kf[:stop] #prints the whole thing
	else:
		key = kf[start:stop]
	key_location = stop

	result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), ui, key))

	print("Here ya go!\n{}\n".format("".join(result)))

	return key_location


print("******************Welcome to our OTP implementation!******************")
c = startup(0)
while c >= 0:
	c = encrypt(c)

# 51466d4e5f575538195551416e4f5300413f1b5008684d5504384157046e4959
