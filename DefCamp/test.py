#!/usr/bin/env python3
import codecs
flag = b'242712673639869973827786401934639193473972235217215301'
hflag = codecs.encode(flag,'hex')
# print(hflag)
# print(int(hflag[2:]))
iflag = int(hflag[2:], 16)
print(str(iflag))
i = 0
while i < 21:
    print(i)
    print(str(iflag)[i:i+2] )
    i = i + 2
# r = ""
# tall = [244, 1917, 812, 33, 920]
# for i in range(5):
#     r += str(tall[i])
# print(r)