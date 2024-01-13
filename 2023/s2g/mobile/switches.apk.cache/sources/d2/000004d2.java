package com.badlogic.gdx.utils.compression;

/* loaded from: classes.dex */
public class CRC {
    public static int[] Table = new int[256];
    int _value = -1;

    static {
        for (int i = 0; i < 256; i++) {
            int r = i;
            for (int j = 0; j < 8; j++) {
                if ((r & 1) != 0) {
                    r = (r >>> 1) ^ (-306674912);
                } else {
                    r >>>= 1;
                }
            }
            Table[i] = r;
        }
    }

    public void Init() {
        this._value = -1;
    }

    public void Update(byte[] data, int offset, int size) {
        for (int i = 0; i < size; i++) {
            int[] iArr = Table;
            int i2 = this._value;
            this._value = iArr[(data[offset + i] ^ i2) & 255] ^ (i2 >>> 8);
        }
    }

    public void Update(byte[] data) {
        for (byte b : data) {
            int[] iArr = Table;
            int i = this._value;
            this._value = iArr[(b ^ i) & 255] ^ (i >>> 8);
        }
    }

    public void UpdateByte(int b) {
        int[] iArr = Table;
        int i = this._value;
        this._value = iArr[(i ^ b) & 255] ^ (i >>> 8);
    }

    public int GetDigest() {
        return this._value ^ (-1);
    }
}