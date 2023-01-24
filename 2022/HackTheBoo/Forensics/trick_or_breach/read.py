from scapy.all import *
import requests
import codecs

pcap = PcapReader('capture.pcap')
urls = []
subs = []
j = 0

for p in pcap:
    pkt = str(p.payload)
    i = pkt.index("com")
    url = pkt[i-69:i+3].replace("\\x0b", ".").replace("\\x03", ".")
    if (j % 2 == 0 and j != 614):
        urls.append(url)
        subs.append(url[:50])
    j += 1

flags = []
for h in range(len(subs[0])):
    pb = ""
    for k in range(len(subs)):
        pb += subs[k][h]
    flags.append(pb)

# for flag in flags: 
#     if "7b" in flag and "7d" in flag: 
#         print(flag)

for sub in subs:
    if "7b" in sub and "7d" in sub: 
        print(sub)

# for url in urls:
#     prot = "http://"
#     try:
#         r = requests.get(prot + url)
#         if "Failed to establish" not in r.text:
#             print(r.text)
#             print(prot + url)
#     except:
#         continue
