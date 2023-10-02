# run on armv7 machine
as sc.s -o sc.o && ld -s sc.o -o sc
objcopy -O binary sc sc.bin
hexdump -v -e '1/1 "%02x" ""' sc.bin
echo ""

# output with current sc.s:
# 00482de900608be200b08de201dc4de204102de57450a0e304502de5677e02e31d8e01e3085987e004502de52f7606e35b8801e3085987e004502de52f7106e3078700e3085a87e004502de57250a0e304502de500108de204008de2667c06e3c28e0ce3885787e04c70a0e3a78800e3884487e034ff2fe104002de54010a0e380004be20470a0e32b8504e3083387e004209de433ff2fe180004be22070a0e3458504e3083387e033ff2fe100d04be20088bde8