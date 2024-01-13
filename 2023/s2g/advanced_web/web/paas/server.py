#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, render_template
import subprocess

app = Flask(__name__)

@app.route("/")
def display():
    return render_template("index.html")

@app.route("/ping", methods=["POST"])
def statistics():
    try: # if timeout is specified
        timeout,ㅤ= [*request.json.values()]
        timeout  =  int(timeout) # prevents command injection

        commands = [  "ping -c1 google.com",  "ping -c1 bing.com",ㅤ]

        exit_status = sum(subprocess.Popen(f"timeout {timeout}s {c}", shell=True).wait() for c in commands)
    except (ValueError, AttributeError): # if timeout is not specified
        commands = [  "ping -c1 google.com",  "ping -c1 bing.com",  ]
        exit_status = sum(subprocess.Popen(c, shell=True).wait() for c in commands)

    if exit_status == 0:
        return "google.com and bing.com are both responsive!"
    else:
        return "Failed to ping google.com and bing.com"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999)
