package com.badlogic.gdx.utils;

import java.io.UnsupportedEncodingException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Base64Coder {
    private static final String systemLineSeparator = "\n";
    public static final CharMap regularMap = new CharMap('+', '/');
    public static final CharMap urlsafeMap = new CharMap('-', '_');

    /* loaded from: classes.dex */
    public static class CharMap {
        protected final char[] encodingMap = new char[64];
        protected final byte[] decodingMap = new byte[128];

        public CharMap(char char63, char char64) {
            int i = 0;
            char c = 'A';
            while (c <= 'Z') {
                this.encodingMap[i] = c;
                c = (char) (c + 1);
                i++;
            }
            char c2 = 'a';
            while (c2 <= 'z') {
                this.encodingMap[i] = c2;
                c2 = (char) (c2 + 1);
                i++;
            }
            char c3 = '0';
            while (c3 <= '9') {
                this.encodingMap[i] = c3;
                c3 = (char) (c3 + 1);
                i++;
            }
            char[] cArr = this.encodingMap;
            int i2 = i + 1;
            cArr[i] = char63;
            int i3 = i2 + 1;
            cArr[i2] = char64;
            int i4 = 0;
            while (true) {
                byte[] bArr = this.decodingMap;
                if (i4 >= bArr.length) {
                    break;
                }
                bArr[i4] = -1;
                i4++;
            }
            for (int i5 = 0; i5 < 64; i5++) {
                this.decodingMap[this.encodingMap[i5]] = (byte) i5;
            }
        }

        public byte[] getDecodingMap() {
            return this.decodingMap;
        }

        public char[] getEncodingMap() {
            return this.encodingMap;
        }
    }

    public static String encodeString(String s) {
        return encodeString(s, false);
    }

    public static String encodeString(String s, boolean useUrlsafeEncoding) {
        try {
            return new String(encode(s.getBytes("UTF-8"), (useUrlsafeEncoding ? urlsafeMap : regularMap).encodingMap));
        } catch (UnsupportedEncodingException e) {
            return BuildConfig.FLAVOR;
        }
    }

    public static String encodeLines(byte[] in) {
        return encodeLines(in, 0, in.length, 76, systemLineSeparator, regularMap.encodingMap);
    }

    public static String encodeLines(byte[] in, int iOff, int iLen, int lineLen, String lineSeparator, CharMap charMap) {
        return encodeLines(in, iOff, iLen, lineLen, lineSeparator, charMap.encodingMap);
    }

    public static String encodeLines(byte[] in, int iOff, int iLen, int lineLen, String lineSeparator, char[] charMap) {
        int blockLen = (lineLen * 3) / 4;
        if (blockLen <= 0) {
            throw new IllegalArgumentException();
        }
        int lines = ((iLen + blockLen) - 1) / blockLen;
        int bufLen = (((iLen + 2) / 3) * 4) + (lineSeparator.length() * lines);
        StringBuilder buf = new StringBuilder(bufLen);
        int ip = 0;
        while (ip < iLen) {
            int l = Math.min(iLen - ip, blockLen);
            buf.append(encode(in, iOff + ip, l, charMap));
            buf.append(lineSeparator);
            ip += l;
        }
        return buf.toString();
    }

    public static char[] encode(byte[] in) {
        return encode(in, regularMap.encodingMap);
    }

    public static char[] encode(byte[] in, CharMap charMap) {
        return encode(in, 0, in.length, charMap);
    }

    public static char[] encode(byte[] in, char[] charMap) {
        return encode(in, 0, in.length, charMap);
    }

    public static char[] encode(byte[] in, int iLen) {
        return encode(in, 0, iLen, regularMap.encodingMap);
    }

    public static char[] encode(byte[] in, int iOff, int iLen, CharMap charMap) {
        return encode(in, iOff, iLen, charMap.encodingMap);
    }

    public static char[] encode(byte[] in, int iOff, int iLen, char[] charMap) {
        int ip;
        int ip2;
        int oDataLen = ((iLen * 4) + 2) / 3;
        int oLen = ((iLen + 2) / 3) * 4;
        char[] out = new char[oLen];
        int ip3 = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip3 < iEnd) {
            int ip4 = ip3 + 1;
            int i0 = in[ip3] & 255;
            int ip5 = 0;
            if (ip4 < iEnd) {
                ip = ip4 + 1;
                ip2 = in[ip4] & 255;
            } else {
                ip = ip4;
                ip2 = 0;
            }
            if (ip < iEnd) {
                int ip6 = ip + 1;
                int i = in[ip] & 255;
                ip = ip6;
                ip5 = i;
            }
            int o0 = i0 >>> 2;
            int o1 = ((i0 & 3) << 4) | (ip2 >>> 4);
            int o2 = ((ip2 & 15) << 2) | (ip5 >>> 6);
            int o3 = ip5 & 63;
            int op2 = op + 1;
            out[op] = charMap[o0];
            int op3 = op2 + 1;
            out[op2] = charMap[o1];
            char c = '=';
            out[op3] = op3 < oDataLen ? charMap[o2] : '=';
            int op4 = op3 + 1;
            if (op4 < oDataLen) {
                c = charMap[o3];
            }
            out[op4] = c;
            op = op4 + 1;
            ip3 = ip;
        }
        return out;
    }

    public static String decodeString(String s) {
        return decodeString(s, false);
    }

    public static String decodeString(String s, boolean useUrlSafeEncoding) {
        return new String(decode(s.toCharArray(), (useUrlSafeEncoding ? urlsafeMap : regularMap).decodingMap));
    }

    public static byte[] decodeLines(String s) {
        return decodeLines(s, regularMap.decodingMap);
    }

    public static byte[] decodeLines(String s, CharMap inverseCharMap) {
        return decodeLines(s, inverseCharMap.decodingMap);
    }

    public static byte[] decodeLines(String s, byte[] inverseCharMap) {
        char[] buf = new char[s.length()];
        int p = 0;
        for (int ip = 0; ip < s.length(); ip++) {
            char c = s.charAt(ip);
            if (c != ' ' && c != '\r' && c != '\n' && c != '\t') {
                buf[p] = c;
                p++;
            }
        }
        return decode(buf, 0, p, inverseCharMap);
    }

    public static byte[] decode(String s) {
        return decode(s.toCharArray());
    }

    public static byte[] decode(String s, CharMap inverseCharMap) {
        return decode(s.toCharArray(), inverseCharMap);
    }

    public static byte[] decode(char[] in, byte[] inverseCharMap) {
        return decode(in, 0, in.length, inverseCharMap);
    }

    public static byte[] decode(char[] in, CharMap inverseCharMap) {
        return decode(in, 0, in.length, inverseCharMap);
    }

    public static byte[] decode(char[] in) {
        return decode(in, 0, in.length, regularMap.decodingMap);
    }

    public static byte[] decode(char[] in, int iOff, int iLen, CharMap inverseCharMap) {
        return decode(in, iOff, iLen, inverseCharMap.decodingMap);
    }

    public static byte[] decode(char[] in, int iOff, int iLen, byte[] inverseCharMap) {
        int ip;
        char c;
        if (iLen % 4 != 0) {
            throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
        }
        int iLen2 = iLen;
        while (iLen2 > 0 && in[(iOff + iLen2) - 1] == '=') {
            iLen2--;
        }
        int oLen = (iLen2 * 3) / 4;
        byte[] out = new byte[oLen];
        int ip2 = iOff;
        int iEnd = iOff + iLen2;
        int op = 0;
        while (ip2 < iEnd) {
            int ip3 = ip2 + 1;
            char c2 = in[ip2];
            int ip4 = ip3 + 1;
            char c3 = in[ip3];
            int ip5 = 65;
            if (ip4 < iEnd) {
                ip = ip4 + 1;
                c = in[ip4];
            } else {
                ip = ip4;
                c = 'A';
            }
            if (ip < iEnd) {
                int ip6 = ip + 1;
                char c4 = in[ip];
                ip = ip6;
                ip5 = c4;
            }
            if (c2 > 127 || c3 > 127 || c > 127 || ip5 > 127) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int b0 = inverseCharMap[c2];
            int b1 = inverseCharMap[c3];
            int b2 = inverseCharMap[c];
            int b3 = inverseCharMap[ip5];
            if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int o0 = (b0 << 2) | (b1 >>> 4);
            int o1 = ((b1 & 15) << 4) | (b2 >>> 2);
            int iLen3 = iLen2;
            int iLen4 = ((b2 & 3) << 6) | b3;
            int op2 = op + 1;
            int iEnd2 = iEnd;
            out[op] = (byte) o0;
            if (op2 < oLen) {
                out[op2] = (byte) o1;
                op2++;
            }
            if (op2 >= oLen) {
                op = op2;
            } else {
                out[op2] = (byte) iLen4;
                op = op2 + 1;
            }
            iLen2 = iLen3;
            ip2 = ip;
            iEnd = iEnd2;
        }
        return out;
    }

    private Base64Coder() {
    }
}