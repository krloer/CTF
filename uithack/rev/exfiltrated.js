const enc_flag = "3c3d1c29020859064f115e4242471011434147686e046a3e0f316b585d540b3133585a09124153544e7d";
const _0x6ee0 = "never gonna give you up";
const _0x10fafd = "never gonna let you down";

function _beard(inp, len, i) {
    let a = inp["ch" + _0x6ee0[10] + "rC" + _0x10fafd[21] + _0x10fafd[20] + "eAt"](i);
    let b = inp["ch" + _0x6ee0[10] + "rC" + _0x10fafd[21] + _0x10fafd[20] + "eAt"](i+1 % len);
    let res = a ^ b;
    return res.toString(0x10).padStart(0b10, "0");
};



const _0x1695 = (_0xde) => {
    let _0x10bc = ['What\x20is\x20the\x20flag?\x20', '1448386GEOWEF', '1783000ecBLBo', 'Correct!', 'o', '25cMJKVA', '1112876yryjDY', '14NiBVWH', 'question', 'length', 'charCodeAt', '801VWpneM', 'log', '105140VZfvyP', 'readline', '2463672KMPYgA', '2498096OxrSLX', 'stdout', '4472832SmweuI', 'console', 'Wrong!'];
    return _0x10bc[_0xde];
};

const forEach = input => {
    let res = "";
    for (let i = 0x0; i < input["length"]; i++) {
        res += _beard(input, input["length"], i);
    }
    return res;
};

const _aldk = (_0x12e, _0x12f) => {
    const _0x1697 = () => {
        return console[_0x10fafd[12] + _0x1695(0x04) + _0x6ee0[0b00110]];
    };
    return _0x1697;
};

forEach("abcdefghijklmnopqrstuvwxyz0123456789AAAAAA")

const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('What is the password? ', (_ab1d2f3) => {
    const _a0be = _aldk(0x68, 0x1)();
    forEach(_ab1d2f3) === enc_flag ? _a0be(_0x1695(3)) : bl_3(_0x1695(20)), rl["close"]();
});

