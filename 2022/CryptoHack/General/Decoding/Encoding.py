#!/usr/bin/env python3

from pwn import * 
import json
import base64
import codecs
from Crypto.Util.number import *

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode(encoded_string, encoded_type):
	print(type(encoded_string))
	if encoded_type == "base64":
		return bytes(base64.b64decode(encoded_string)).decode("utf-8")
	elif encoded_type == "hex":
		return bytes(bytes.fromhex(encoded_string)).decode("utf-8")
	elif encoded_type == "rot13":
		return codecs.decode(encoded_string, 'rot_13')
	elif encoded_type == "utf-8":
		list = encoded_string
		ord = ""
		for i in list:
			ord += chr(i)
		return ord
	else:
		return bytes(long_to_bytes(int(encoded_string,16))).decode("utf-8")


for i in range(100):
	print(i)

	received = json_recv()

	print("Received type: ")
	print(received["type"])
	print("Received encoded value: ")
	print(received["encoded"])
	encoded_type = received["type"]
	encoded_string = received["encoded"]

	to_send = {
	    "decoded": decode(encoded_string, encoded_type)
	}
	json_send(to_send)

print(json_recv())
