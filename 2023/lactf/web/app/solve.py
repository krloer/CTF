import base64

#tested in utils.py

payload = base64.a85decode(b"\\\\\\'OR/**/1==1-----")
with open("payload.txt", "wb") as file:
    file.write(payload)