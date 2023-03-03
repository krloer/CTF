hash = '9f05b36e35b5f2dcfa5a517e1895ac96e6498166d48f9df5e94cd9f3f790616f'
ciphertext = '51hXqew+LPKokFDOgdFzz0IpUq9oNMbEJy4fX5HvLjI='

function checkPassword() {
    result.innerText = CryptoJS.AES.decrypt(
        {
            ciphertext: CryptoJS.enc.Base64.parse(ciphertext)
        },
        CryptoJS.enc.Utf8.parse(password.value),
        {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.ZeroPadding
        }
    ).toString(CryptoJS.enc.Utf8)
}

password.oninput = () => checkPassword();