import string
import os

ALPHABET = string.ascii_letters + string.digits + "!_?."

for i in ALPHABET:
    print(i)
    os.system(f"sed -i \"s/buffer: \['./buffer: \['{i}/g\" scripts/0.js")
    os.system("node -e 'require(\"./scripts/0.js\").go()'")
