from requests import *
import string
from base64 import b64decode
from pwn import *
from Crypto.Cipher import AES

chars = string.ascii_letters+string.digits+"_/\\!?.,'}{"
enc = "U2FsdGVkX19+39o87YO7Zj+D9Og1WLYWUMqboh+IWypf1plXoTmOcBysQuPa8wye"
key = b'a_wonderful_key_that_is_wonder:)'

url = "https://bluehens-oracle.chals.io/ask/"
flag = "UDCTF"
i = 5

# while True:
#     for c in chars:
#         attempt = url + flag + c
#         req = get(attempt.ljust(68, "A"))
#         result = req.text[req.text.index("<strong>")+8:req.text.index("</strong>")]
#         if result[i*2:(i+1)*2] == enc[i*2:(i+1)*2]:
#             # flag += c
#             print(c)
#             print(result[i*2:(i+1)*2])
#             print(enc[i*2:(i+1)*2])
            
#             print(flag)
#     i += 1
#     print("Next")

enc = base64.base64decode(enc)
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(enc))
