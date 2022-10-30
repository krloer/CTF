#UDCTF{y0u'v3_b3en_bytt3n_by_th3_sn4ke}

tmp = input('input> ')
if not len(tmp) == 38:
    exit(1)
if not sum(tmp.encode()) == 3538:
    exit(1)
if not tmp[:6] == 'UDCTF{':
    exit(1)
if not tmp[-1] == '}':
    exit(1)
if not ord(tmp[5]) - 2 == ord(tmp[6]):
    exit(1)
if not tmp[7] == chr(int(str(ord(tmp[3]))[::-1])):
    exit(1)
if not ord(tmp[7]) - 9 == ord(tmp[9]):
    exit(1)
x = ord(tmp[8])
y = ord(tmp[10])
if not x + y == 235:
    exit(1)
if not max(x, y) < 119:
    exit(1)
if not tmp[11:24].encode().hex() == '335f6233656e5f62797474336e':
    exit(1)
if not tmp[24] == tmp[27]:
    exit(1)
if not tmp[27] == tmp[31]:
    exit(1)
if not ord(tmp[25]) * ord(tmp[26]) == 11858:
    exit(1)
if not ord(tmp[28]) * ord(tmp[29]) * ord(tmp[30]) == 615264:
    exit(1)
yy = list(''.join(map(lambda x: str(ord(x))
, tmp[32:37])))
yy.sort()
if not ''.join(yy) == '00011111112557':
    exit(1)
if not tmp[34] == '4':
    exit(1)
print('You win')
