from flask import Flask, Response, send_file
import re

app = Flask(__name__)

@app.after_request
def redact_flag(response):
    return Response(re.sub(b'S2G{.*}', b'REDACTED', b''.join(list(response.response))))

@app.route('/')
def index():
    return send_file('flag.html')
