prompt = function (fun, x) {
    let answer = fun(x);
    
    if (!/^[a-z]{13}$/.exec(answer)) return "";
  
    answer = "rebecccapurple"
    let a = [], b = [], c = [], d = [], e = [], f = [], g = [], h = [], i = [], j = [], k = [], l = [], m = [];
    let n = "blue";
    a.push(a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, b, a, a, a, a, a, a, a, a);
    b.push(b, b, b, b, c, b, a, a, b, b, a, b, a, b, a, a, b, a, b, a, a, b, a, b, a, b);
    c.push(a, d, b, c, a, a, a, c, b, b, b, a, b, c, a, b, b, a, c, c, b, a, b, a, c, c);
    d.push(c, d, c, c, e, d, d, c, c, c, c, b, c, c, d, c, b, d, a, d, c, c, c, a, d, c);
    e.push(a, e, f, c, d, e, a, e, c, d, c, c, c, d, a, e, b, b, a, d, c, e, b, b, a, a);
    f.push(f, d, g, e, d, e, d, c, b, f, f, f, a, f, e, f, f, d, a, b, b, b, f, f, a, f);
    g.push(h, a, c, c, g, c, b, a, g, e, e, c, g, e, g, g, b, d, b, b, c, c, d, e, b, f);
    h.push(c, d, a, e, c, b, f, c, a, e, a, b, a, g, e, i, g, e, g, h, d, b, a, e, c, b);
    i.push(h, a, d, b, d, c, d, b, f, a, b, b, i, d, g, a, a, a, h, i, j, c, e, f, d, d);
    j.push(b, f, c, f, i, c, b, b, c, j, i, e, e, j, g, j, c, k, c, i, h, g, g, g, a, d);
    k.push(i, k, c, h, h, j, c, e, a, f, f, h, e, g, c, l, c, a, e, f, d, c, f, f, a, h);
    l.push(j, k, j, a, a, i, i, c, d, c, a, m, a, g, f, j, j, k, d, g, l, f, i, b, f, l);
    m.push(c, c, e, g, n, a, g, k, m, a, h, h, l, d, d, g, b, h, d, h, e, l, k, h, k, f);
    walk = a;

    for (let c of answer) {
    console.log(c.charCodeAt() - 97);
    walk = walk[c.charCodeAt() - 97];
    console.log(walk);
    }
  
    if (walk != "blue") return "";
  
    return {toString: () => _ = window._ ? answer : "blue"};
  
  }.bind(null, prompt);
  
  eval(document.getElementById('challenge').innerText);