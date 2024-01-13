export memory a(initial: 256, max: 256);

global g_a:int = 66576;

export table d:funcref(min: 1, max: 1);

data d_a(offset: 1024) = "}\00S2G{";

export function b() {
  nop
}

export function g(a:int):int {
  a = g_a - a & -16;
  g_a = a;
  return a;
}

export function f(a:int) {
  g_a = a
}

export function e():int {
  return g_a
}

export function c(a:ubyte_ptr):int {
  var b:{ a:ubyte, b:ubyte }
  var d:int;
  var c:int;
  var e:int;
  var h:int;
  if (
    {
      b = a;
      if (eqz(b & 3)) goto B_d;
      0;
      if (eqz(a[0])) goto B_b;
      loop L_e {
        b = b + 1;
        if (eqz(b & 3)) goto B_d;
        if (b.a) continue L_e;
      }
      goto B_c;
      label B_d:
      loop L_f {
        d = b;
        b = d + 4;
        c = d[0]:int;
        if (eqz(((c ^ -1) & c - 16843009) & -2139062144)) continue L_f;
      }
      loop L_g {
        b = d;
        d = b + 1;
        if (b.a) continue L_g;
      }
      label B_c:
      b - a;
      label B_b:
    } !=
    37) goto B_a;
  d = 0;
  var g:int = 4;
  var f:ubyte_ptr = 1026;
  b = a;
  c = b.a;
  if (eqz(c)) goto B_h;
  loop L_i {
    if (c != (e = f[0])) goto B_j;
    if (eqz(e)) goto B_j;
    g = g - 1;
    if (eqz(g)) goto B_j;
    f = f + 1;
    c = b.b;
    b = b + 1;
    if (c) continue L_i;
    goto B_h;
    label B_j:
  }
  d = c;
  label B_h:
  if ((d & 255) - f[0]) goto B_a;
  b = 1024;
  e = d_a[0]:ubyte;
  d = a + 36;
  c = d[0]:ubyte;
  if (eqz(c)) goto B_k;
  if (c != e) goto B_k;
  loop L_l {
    e = b.b;
    c = d[1]:ubyte;
    if (eqz(c)) goto B_k;
    b = b + 1;
    d = d + 1;
    if (c == e) continue L_l;
  }
  label B_k:
  if (c - e) goto B_a;
  if (a[5] != 99) goto B_m;
  if (a[25] != 54) goto B_m;
  if (a[4] != 50) goto B_m;
  if (a[23] != 50) goto B_m;
  if (a[20] != 57) goto B_m;
  if (a[29] != 100) goto B_m;
  if (a[10] != 99) goto B_m;
  if (a[6] != 55) goto B_m;
  if (a[16] != 53) goto B_m;
  if (a[30] != 102) goto B_m;
  if (a[8] != 54) goto B_m;
  if (a[34] != 51) goto B_m;
  if (a[19] != 54) goto B_m;
  if (a[9] != 51) goto B_m;
  if (a[18] != 51) goto B_m;
  if (a[17] != 49) goto B_m;
  if (a[12] != 99) goto B_m;
  if (a[7] != 51) goto B_m;
  if (a[15] != 98) goto B_m;
  if (a[13] != 49) goto B_m;
  if (a[32] != 97) goto B_m;
  if (a[31] != 99) goto B_m;
  if (a[35] != 48) goto B_m;
  if (a[11] != 98) goto B_m;
  if (a[28] != 53) goto B_m;
  if (a[21] != 101) goto B_m;
  if (a[14] != 56) goto B_m;
  if (a[24] != 97) goto B_m;
  if (a[27] != 56) goto B_m;
  if (a[33] != 49) goto B_m;
  if (a[26] != 55) goto B_m;
  h = 1;
  if (a[22] == 49) goto B_a;
  label B_m:
  h = 0;
  label B_a:
  return h;
}

