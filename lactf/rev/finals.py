# for (local_10 = local_118; *local_10 != '\0'; local_10 = local_10 + 1) {
#       *local_10 = (char)((long)(*local_10 * 0x11) % 0xfd);
# }


enc = [0x0e, 0xc9, 0x9d, 0xb8, 0x26, 0x83, 0x26, 0x41, 0x74, 0xe9, 0x26, 0xa5, 0x83, 0x94, 0x0e, 0x63, 0x37, 0x37, 0x37]

correct = []

correct = "".join(chr(i) for ans in enc for i in range(0xff) if  i*0x11 % 0xfd == ans)
print(correct)
# for ans in enc:
#     for i in range(0xff):
#         if i*0x11 % 0xfd == ans:
#             correct.append(chr(i))

# print("".join(correct))
                        