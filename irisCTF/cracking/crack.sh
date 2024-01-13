#!/usr/bin/env bash

hashcat -m 3200 -a 0 pw_hash wordlist.txt
hashcat -m 25600 -a 0 pw_hash wordlist.txt
hashcat -m 25800 -a 0 pw_hash wordlist.txt
hashcat -m 28400 -a 0 pw_hash wordlist.txt
