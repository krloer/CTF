package com.badlogic.gdx.utils;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public class LittleEndianInputStream extends FilterInputStream implements java.io.DataInput {
    private DataInputStream din;

    public LittleEndianInputStream(InputStream in) {
        super(in);
        this.din = new DataInputStream(in);
    }

    @Override // java.io.DataInput
    public void readFully(byte[] b) throws IOException {
        this.din.readFully(b);
    }

    @Override // java.io.DataInput
    public void readFully(byte[] b, int off, int len) throws IOException {
        this.din.readFully(b, off, len);
    }

    @Override // java.io.DataInput
    public int skipBytes(int n) throws IOException {
        return this.din.skipBytes(n);
    }

    @Override // java.io.DataInput
    public boolean readBoolean() throws IOException {
        return this.din.readBoolean();
    }

    @Override // java.io.DataInput
    public byte readByte() throws IOException {
        return this.din.readByte();
    }

    @Override // java.io.DataInput
    public int readUnsignedByte() throws IOException {
        return this.din.readUnsignedByte();
    }

    @Override // java.io.DataInput
    public short readShort() throws IOException {
        int low = this.din.read();
        int high = this.din.read();
        return (short) ((high << 8) | (low & 255));
    }

    @Override // java.io.DataInput
    public int readUnsignedShort() throws IOException {
        int low = this.din.read();
        int high = this.din.read();
        return ((high & 255) << 8) | (low & 255);
    }

    @Override // java.io.DataInput
    public char readChar() throws IOException {
        return this.din.readChar();
    }

    @Override // java.io.DataInput
    public int readInt() throws IOException {
        int[] res = new int[4];
        for (int i = 3; i >= 0; i--) {
            res[i] = this.din.read();
        }
        return ((res[0] & 255) << 24) | ((res[1] & 255) << 16) | ((res[2] & 255) << 8) | (res[3] & 255);
    }

    @Override // java.io.DataInput
    public long readLong() throws IOException {
        int[] res = new int[8];
        for (int i = 7; i >= 0; i--) {
            res[i] = this.din.read();
        }
        return ((res[0] & 255) << 56) | ((res[1] & 255) << 48) | ((res[2] & 255) << 40) | ((res[3] & 255) << 32) | ((res[4] & 255) << 24) | ((res[5] & 255) << 16) | ((res[6] & 255) << 8) | (res[7] & 255);
    }

    @Override // java.io.DataInput
    public float readFloat() throws IOException {
        return Float.intBitsToFloat(readInt());
    }

    @Override // java.io.DataInput
    public double readDouble() throws IOException {
        return Double.longBitsToDouble(readLong());
    }

    @Override // java.io.DataInput
    public final String readLine() throws IOException {
        return this.din.readLine();
    }

    @Override // java.io.DataInput
    public String readUTF() throws IOException {
        return this.din.readUTF();
    }
}