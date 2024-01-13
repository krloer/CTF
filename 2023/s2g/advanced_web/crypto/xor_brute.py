enc = "AXMJKRkBAB4HAR4GEwIFFwUz"

flag_start = "S2G{"

# def encrypt(message, key):
#     return bytes(message ^ key)

known_key = [ord(enc[i]) ^ ord(flag_start[i]) for i in range(4)]
# print(known_key)

for a in range(0,256):
    for b in range(0,256):
        for c in range(0,256):
            flag = ""
            key = known_key + [a, b, c]
            # print(key)
            flag = [key[i%len(key)] ^ ord(c) for i, c in enumerate(enc)]
            flag = "".join([chr(c) for c in flag])
            if flag[-1] == "}" and "_" in flag:
                print(flag + "CHECK!!!!!!!!!!!!!!!")
            elif flag[-1] == "}":
                print(flag)
