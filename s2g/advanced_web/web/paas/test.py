#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess

request = {"any": "{{2+2}}"}

try: # if timeout is specified
    timeout, = [*request.values()]
    timeout  =  int(timeout) # prevents command injection
    print(timeout)
    commands = [  "ping -c1 google.com",  "ping -c1 bing.com", ]

    print("\n\nRunning")
    exit_status = sum(subprocess.Popen(f"timeout {timeout}s {c}", shell=True).wait() for c in commands)
    print("Done\n\n")


except (ValueError, AttributeError): # if timeout is not specified
    print("FAILED")
    print("\n\nRunning")
    commands = [  "ping -c1 google.com",  "ping -c1 bing.com",  ]
    exit_status = sum(subprocess.Popen(c, shell=True).wait() for c in commands)
    print("Done\n\n")

if exit_status == 0:
    print("google.com and bing.com are both responsive!")
else:
    print("Failed to ping google.com and bing.com")

