package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.StreamUtils;

/* loaded from: classes.dex */
public class DataBuffer extends DataOutput {
    private final StreamUtils.OptimizedByteArrayOutputStream outStream;

    public DataBuffer() {
        this(32);
    }

    public DataBuffer(int initialSize) {
        super(new StreamUtils.OptimizedByteArrayOutputStream(initialSize));
        this.outStream = (StreamUtils.OptimizedByteArrayOutputStream) this.out;
    }

    public byte[] getBuffer() {
        return this.outStream.getBuffer();
    }

    public byte[] toArray() {
        return this.outStream.toByteArray();
    }
}