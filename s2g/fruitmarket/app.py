from flask import Flask, session
from fruits import fruits
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

@app.before_request
def set_session():
    if 'balance' not in session:
        session['balance'] = 100
        session['fruits']  = []

@app.route('/list')
def list():
    return fruits

@app.route('/buy/<int:id>', methods=['POST'])
def buy(id):
    if id not in fruits:
        return 'Fruit not found.', 404

    fruit = fruits[id]

    if session['balance'] < fruit['price']:
        return 'You do not have enough money to buy that fruit.', 400

    session['fruits'].append(id)
    session['balance'] -= fruit['price']

    return f'Successfully bought a(n) {fruit["name"]}.'

@app.route('/sell/<int:id>', methods=['POST'])
def sell(id):
    if id not in fruits:
        return 'Fruit not found.', 404
    
    if id not in session['fruits']:
        return 'You do not own that fruit.', 400

    session['fruits'].remove(id)
    session['balance'] += fruits[id]['price']

@app.route('/flag')
def flag():
    if session['balance'] > 100:
        return 'S2G{fake_flag}'
    else:
        return 'Nope...', 400
