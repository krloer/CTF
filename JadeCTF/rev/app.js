require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const fs = require('fs');

app.set('etag', false);
app.use(bodyParser.urlencoded());
app.set('view engine', 'ejs');
app.use(express.static('public'));

let memory = [0];
const memorySize = 100;
const errorDecoded = 'Idiot!';
let pointer = 1;

let program = [62, 91, 43, 43, 46, 62, 93, 91, 60, 93, 62, 91, 43, 45, 43, 46, 62, 93];
let programPtr = 0;
let braces = [];

function resetMemory() {
    memory = [0];
    pointer = 1;

    program = [62, 91, 43, 43, 46, 62, 93, 91, 60, 93, 62, 91, 43, 45, 43, 46, 62, 93];
    programPtr = 0;
    braces = [];
}

function populateMemory(iv, l) {
    for ( let i = l-1; i >= 0; i-- ) {
        memory.push(iv[i].charCodeAt(0)); // [char code of first value] * length of input
    }
    
    pointer = l+1; //length + 1
    for ( let i = pointer; i < memorySize; i++ ) {
        memory.push(0); // memory append [0,0,0,0,0] up to len 100
    }

    pointer = 0;
}

let gg = {
    fun_0x60: function () {
        pointer--; // <
    },

    fun_0x62: function () {
        pointer++; // >
    },

    fun_0x43: function () {
        memory[pointer]++; // +
    },

    fun_0x45: function () {
        memory[pointer]--; // -
    },

    fun_0x91: function () { // [
        if( memory[pointer] == 0 ){
            while( program[programPtr] != "]" && programPtr <= program.length){
                programPtr += 1;
            }
        } else {
            braces.push(programPtr);
        }
    },

    fun_0x93: function () {
        if (braces.length > 0){
            programPtr = braces.pop();
            programPtr -= 1;
        }
    },

    fun_0xgg: function (s) { // need '{"admin":"true", "guest":"false", "organization":"cyberlabs"}'
        try {
            return JSON.parse(s);
        } catch ( e ) {
            return false;
        }
    }
}; 

function decode(encoded) {
    let l = encoded.length;
    if ( !l || l <= 0 || l >= memorySize ) {
        return errorDecoded;
    }

    populateMemory(encoded, l); //pointer = 0 and memory = [0,0,0,0,0] len 100
    let decoded = ''; // program = [62, 91, 43, 43, 46, 62, 93, 91, 60, 93, 62, 91, 43, 45, 43, 46, 62, 93]; len 18
    // 60: <, 62: >, 43: +, 45: -, 91: [, 93: ]

    /*
    > pointer = 1
    [ while (*ptr){address += 2}
    ++
    .
    >
    ]
    [
    <
    ]
    >
    [
    +
    -
    +
    .
    >
    ]
    
    >[++.>][<]>[+-+.>]
    */
    while ( programPtr < program.length ) { // 
        i = program[programPtr];
        if ( i == 46 ) {
            decoded += String.fromCharCode(memory[pointer]);
            programPtr++;
            continue;
        }
        
        (gg[`fun_0x${i}`])();
        if ( pointer >= memorySize ) {
            return errorDecoded;
        }
        programPtr++;
    }
    resetMemory();
    return gg['fun_0xgg'](decoded);
}

function getFlag() {
    return new Promise((resolve, reject) => {
        fs.readFile('/usr/app/flag.txt', (err, data) => {
            if ( err ) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}


app.get('/', (req, res) => {
    res.render('index', {
        message: ''
    });
});

app.post('/', async (req, res) => {
    try {
        let decoded = decode(req.body.code);
        if ( 
            decoded &&
            decoded.admin === 'true' &&
            decoded.guest === 'false' &&
            decoded.organization === 'cyberlabs' // {"admin":"true", "guest":"false", "organization"="cyberlabs"}
        ) {
            res.render('index', {
                message: await getFlag()
            });
            return;
        }
        res.redirect('/');
    } catch ( error ) {
        console.log(error);
        res.redirect('/');
    }
});

app.listen(4000, () => console.log('Listening on', 4000));