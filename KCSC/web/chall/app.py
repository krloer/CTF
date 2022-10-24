import random
import string
import hashlib
from flask import Flask
from flask import render_template

with open("flag.txt", "r") as f:
    flag = f.read()
 
app = Flask(__name__)

def generate_password():
    rand = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(100))
    return rand

@app.route('/')
@app.route('/<access_key>')
def access(access_key=None):
    password = str(generate_password)[:-10].encode()
    password = hashlib.md5(password).hexdigest()

    return render_template("restricted.html") if != password else render_template("development.html", flag=flag)