# replace_bytes.py01 Choir (Remix)
source_str = '424d8e262c0000000000bad00000bad000006e04000032010000' # got this with xxd -ps file | head -c 52
replace_str = '424d8e262c000000000036000000280000006e04000052030000' # 0x28 = 40 - constant size of InfoHeader, 0x36 = 54 (14 + 40) data offset

#file size = 2893400
#img size = 1134 * x
#1134 * 3 (1 for r,g,b) + (1134 % 4) (bmp padding) = 3404
#2893400/3404 = 850 px -> 0x352 -> 5203 in header (backwards)

with open('tunn3l_vision.bmp', 'rb') as f:
    content = f.read().hex()
content = content.replace(source_str, replace_str)

with open('tunn3l_vision_edited.bmp', 'wb') as f:
    f.write(bytes.fromhex(content))

with open('tunn3l_vision_edited.bmp', 'rb') as f:
    new_content = f.read().hex()