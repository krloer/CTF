# print(bytes('牦浯栠獡汨扩椠灭牯⁴ਪ⁣‽〢㈱㐳㘵㠷ⴹਢ汦灩祰㴠氠浡摢⁡㩸戠瑹獥昮潲桭硥⠨㩭砽攮据摯⡥⸩敨⡸⤩ㅛ㨺崲洫㩛㈺⥝挊敨正‱‽慬扭慤砠›硥瑩⴨⤱椠⁦敬⡮⥸㰠ㄠ‶汥敳丠湯੥档捥㉫㴠氠浡摢⁡㩸攠楸⡴㈭ 晩渠瑯⠠污⡬⁥湩挠映牯攠椠⁮⥸愠摮氠湥砨 㴽㈠‹湡⁤學㨵㘺⁝㴽∠∭㐪愠摮砠挮畯瑮∨∭ 㴽㐠 汥敳丠湯੥档捥㍫㴠氠浡摢⁡ⱸ㩹攠楸⡴㌭ 晩渠瑯愠汬昨昨楬灰⡹⥸⸩敨摸杩獥⡴⸩瑳牡獴楷桴木 潦⁲ⱦ⁧湩稠灩嬨摭ⰵ桳ㅡ猬慨㔲ⰶ桳㍡㐸猬慨㔲崶‬⹹灳楬⡴ⴢ⤢⤩攠獬⁥潎敮渊浡ⱥ猠捥敲⁴‽慭⡰湩異ⱴ嬠圢慨❴⁳潹牵渠浡㽥湜‾Ⱒ∠桗瑡猧礠畯⁲敳牣瑥尿㹮∠⥝挊敨正⠱慮敭਩档捥㉫猨捥敲⥴挊敨正⠳慮敭‬敳牣瑥਩牰湩⡴灯湥∨汦条琮瑸⤢爮慥⡤⤩','u16')[2:])

# exec(bytes('牦浯栠獡汨扩椠灭牯⁴ਪ⁣‽〢㈱㐳㘵㠷ⴹਢ汦灩祰㴠氠浡摢⁡㩸戠瑹獥昮潲桭硥⠨㩭砽攮据摯⡥⸩敨⡸⤩ㅛ㨺崲洫㩛㈺⥝挊敨正‱‽慬扭慤砠›硥瑩⴨⤱椠⁦敬⡮⥸㰠ㄠ‶汥敳丠湯੥档捥㉫㴠氠浡摢⁡㩸攠楸⡴㈭ 晩渠瑯⠠污⡬⁥湩挠映牯攠椠⁮⥸愠摮氠湥砨 㴽㈠‹湡⁤學㨵㘺⁝㴽∠∭㐪愠摮砠挮畯瑮∨∭ 㴽㐠 汥敳丠湯੥档捥㍫㴠氠浡摢⁡ⱸ㩹攠楸⡴㌭ 晩渠瑯愠汬昨昨楬灰⡹⥸⸩敨摸杩獥⡴⸩瑳牡獴楷桴木 潦⁲ⱦ⁧湩稠灩嬨摭ⰵ桳ㅡ猬慨㔲ⰶ桳㍡㐸猬慨㔲崶‬⹹灳楬⡴ⴢ⤢⤩攠獬⁥潎敮渊浡ⱥ猠捥敲⁴‽慭⡰湩異ⱴ嬠圢慨❴⁳潹牵渠浡㽥湜‾Ⱒ∠桗瑡猧礠畯⁲敳牣瑥尿㹮∠⥝挊敨正⠱慮敭਩档捥㉫猨捥敲⥴挊敨正⠳慮敭‬敳牣瑥਩牰湩⡴灯湥∨汦条琮瑸⤢爮慥⡤⤩','u16')[2:])

from hashlib import *
c = "0123456789-"
flippy = lambda x: bytes.fromhex((m:=x.encode().hex())[1::2]+m[::2])
# print(flippy().hexdigest())

check1 = lambda x: exit(-1) if len(x) < 16 else None

check2 = lambda x: exit(-2) if not (all(e in c for e in x) and len(x) == 29 and x[5::6] == "-"*4 and x.count("-") == 4) else None
# check2a = lambda x: exit(-2) if not all(e in c for e in x) else print("passed a")
# check2b = lambda x: exit(-2) if not len(x) == 29 else print("passed b") # secret length 29
# check2c = lambda x: exit(-2) if not x[5::6] == "-"*4 else print("passed c")
# check2d = lambda x: exit(-2) if not x.count("-") == 4 else print("passed d")

check3 = lambda x,y: exit(-3) if not all(f(flippy(x)).hexdigest().startswith(g) for f,g in zip([md5,sha1,sha256,sha384,sha256], y.split("-"))) else None
name, secret = map(input, ["What\'s your name?\\n> ", "What\'s your secret?\\n> "])
print("input:")
print(name)
print("16 <= ", len(name))
print(secret)
print("29 == ", len(secret))
print("---- == ", secret[5::6])
print("=================================")

print(secret.split("-"))
print(md5(flippy(name)).hexdigest())
print([x for x in zip([md5,sha1,sha256,sha384,sha256], secret.split("-"))])

print(f(flippy(name)).hexdigest() for f,g in zip([md5,sha1,sha256,sha384,sha256], secret.split("-")))

print("=================================")
check1(name) # name needs to be longer than 16 bytes
print("passed 1")
check2(secret) # format: xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
print("passed 2")
check3(name, secret)
print(open("flag.txt").read())