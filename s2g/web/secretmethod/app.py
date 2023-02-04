from flask import Flask, request

app = Flask(__name__)
SECRET_METHOD = '...'

@app.route('/', methods=['GET', SECRET_METHOD])
def index():
    if request.method == SECRET_METHOD:
        return 'S2G{fake_flag}'
    return 'The flag is not here!'
