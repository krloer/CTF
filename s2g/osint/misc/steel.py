import requests
import svgwrite
import os
import cv2


s = requests.Session()
r = s.get('http://10.212.138.23:56949/')

coordinates = r.text[r.text.index("<svg"):r.text.index("</svg>")+6]
with open("lmao1.svg","w") as file:
    file.write(coordinates)

os.system("convert lmao1.svg lmao1.png")

img = cv2.imread('lmao1.png')
detect = cv2.QRCodeDetector()
value, points, straight_qrcode = detect.detectAndDecode(img)
secret = value

# print(secret)
token = r.text[r.text.index("hidden"):]
token = token.split("=")[2][1:17]
# print(token)

x = s.post('http://10.212.138.23:56949/captcha', data = {'secret': secret,'token': token})
print(x.text)
