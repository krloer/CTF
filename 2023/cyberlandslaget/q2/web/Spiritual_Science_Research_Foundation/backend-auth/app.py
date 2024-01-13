from flask import Flask, request, abort
from flask_httpauth import HTTPBasicAuth

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pyotp import TOTP, random_base32
from db_settings import get_db_url
from waitress import serve
from models import User
from time import sleep
import hashlib
import socket

app = Flask(__name__)
app.secret_key = random_base32()

not_ready = True
while(not_ready):
    try:
        engine = create_engine(get_db_url(), pool_size=75, max_overflow=0)
        sql_session_maker = sessionmaker(bind=engine)
        sql_session = sql_session_maker()
        not_ready = False
        print("Database ready", flush=True)
    except:
        print("Database not ready", flush=True)
        sleep(3)
        pass

flag = open("flag.txt", "r").read()

hostname=socket.gethostname()   
IPAddr=socket.gethostbyname(hostname)   
@app.after_request
def apply_caching(response):
    response.headers["X-BACKEND-AUTH-IP"] = IPAddr
    return response

auth = HTTPBasicAuth()
@auth.verify_password
def verify_password(username, password):
    if (username == "admin" and validate_creds(username, password)):
        return username
    return None

def hash_password(username, password):
    salt = hashlib.md5(username.encode('utf-8')).hexdigest()
    # long salt, unique per user
    hashed_password = hashlib.md5((f"{salt}_{password.lower()[:6]}").encode('utf-8')).hexdigest()
    return hashed_password

def register_user(username, password, description):
    totp_secret = random_base32()
    sql_session = sql_session_maker()
    try:
        user_object = User()
        user_object.username = username
        user_object.password = hash_password(username, password)
        user_object.description = description
        user_object.totp_secret = totp_secret
        user = sql_session.query(User).filter_by(username=username).first()
        if user == None:
            sql_session.add(user_object)
            sql_session.commit()
        else:
            return {"status": False}
    except Exception as e:
        sql_session.rollback()
        return {"status": False}
    return {"status": True, "totp_secret": totp_secret}

@app.route('/register', methods=['POST'])
def register():
    body = request.get_json()
    username = body.get('username')
    password = body.get('password')
    description = body.get('description')
    return register_user(username, password, description)

def verify_otp(username, provided_otp):
    secret = get_secret(username)
    if secret:
        return provided_otp == TOTP(secret).now()[:4]
    return False

secrets = {}
def get_secret(username):
    if username in secrets:
        return secrets.get(username)
    try:
        sql_session = sql_session_maker()
        user = sql_session.query(User).filter_by(username=username).first()
        if user != None:
            secrets[username] = user.totp_secret
            return user.totp_secret
    except Exception as e:
        pass
    return None

creds = {}
def validate_creds(username, password):
    if username and password:
        password = hash_password(username, password)
        if username == "admin":
            assert password == "8dbadad6b8558891ca60625fd547da21"
        if username in creds:
            return creds.get(username) == password 
        try:
            sql_session = sql_session_maker()
            user = sql_session.query(User).filter_by(username=username,password=password).first()
            sql_session.commit()
            if user != None:
                creds[username] = password
                return True
        except Exception as e:
            pass
    return False

@app.route("/auth", methods=['POST'])
def authenticate():
    body = request.get_json()
    username = body.get('username')
    password = body.get('password')
    return {"validated": validate_creds(username, password)}

@app.route("/otp/<username>")
def otp(username):
    totp_secret = get_secret(username)
    if not totp_secret:
        return abort(400)
    return TOTP(totp_secret).now()[:4]

@app.route("/flag/<otp>")
@auth.login_required
def get_flag(otp):
    if not otp:
        return {"error": "OTP not provided"}
    if not verify_otp("admin", otp):
        return {"error": "OTP invalid"}
    sleep(0.5) # prevent brute force attacks
    return flag

@app.route("/ping")
def ping():
    return "pong"

if __name__ == "__main__":
    serve(app, listen='*:80',threads=100)