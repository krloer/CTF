## Using Baserunner

```
input this as config:
{
  apiKey: 'AIzaSyDN_2EZMN-1QCJ4V13WYUTV4UKA4Im8lLM',
  authDomain: 'websec-ctfs.firebaseapp.com',
  projectId: 'websec-ctfs',
  storageBucket: 'websec-ctfs.appspot.com',
  messagingSenderId: '617149347368',
  appId: '1:617149347368:web:e34a2bf5fe52fb1b77a71d'
}
```

```
input this as query:
window.cfs.collection("sessioncracker").get().then(window.displayReadResults)
.catch((error) => {
    window.displayError(`d: ${error}`);
});
```

```
output:

14445006 => {
  "help": "window.cfs.collection(\"secret\").get().then(window.displayReadResults);",
  "k": "b",
  "first": "AAAABBBB",
  "flag": "window.cfs.collection(\"flag\").get().then(window.displayReadResults);",
  "window.cfs.collection(\"flag\").get().then(window.displayReadResults);": "window.cfs.collection(\"flag\").get().then(window.displayReadResults);"
}
16233679 => {
  "1": "'"
}
17588281 => {
  "supervisor": "BJtfWvgK7n1cInPAdXNL"
}
1919988 => {
  "king": "black"
}
22793283 => {
  "xnull": "pass",
  "xxxx": "pass",
  "{{7*7}}": "pass"
}
24381151 => {
  "asdf": "`",
  "flag": ","
}
51728107 => {
  "Suave Squid": ""
}
72924659 => {
  "supervisor": "BJtfWvgK7n1cInPAdXNL"
}
BJtfWvgK7n1cInPAdXNL => {
  "supervisor": "E6Op9kN9FR6N7fXXhHoL",
  "first": "Charles",
  "last": "Secure"
}
E6Op9kN9FR6N7fXXhHoL => {
  "flag": "UDCTF{l0ok_1t_f6ireb3se}"
}
```
