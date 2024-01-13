package com.badlogic.gdx.utils.compression.rangecoder;

import java.io.IOException;
import java.io.InputStream;
import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public class Decoder {
    static final int kBitModelTotal = 2048;
    static final int kNumBitModelTotalBits = 11;
    static final int kNumMoveBits = 5;
    static final int kTopMask = -16777216;
    int Code;
    int Range;
    InputStream Stream;

    public final void SetStream(InputStream stream) {
        this.Stream = stream;
    }

    public final void ReleaseStream() {
        this.Stream = null;
    }

    public final void Init() throws IOException {
        this.Code = 0;
        this.Range = -1;
        for (int i = 0; i < 5; i++) {
            this.Code = (this.Code << 8) | this.Stream.read();
        }
    }

    public final int DecodeDirectBits(int numTotalBits) throws IOException {
        int result = 0;
        for (int i = numTotalBits; i != 0; i--) {
            this.Range >>>= 1;
            int i2 = this.Code;
            int i3 = this.Range;
            int t = (i2 - i3) >>> 31;
            this.Code = i2 - ((t - 1) & i3);
            result = (result << 1) | (1 - t);
            if ((kTopMask & i3) == 0) {
                this.Code = (this.Code << 8) | this.Stream.read();
                this.Range <<= 8;
            }
        }
        return result;
    }

    public int DecodeBit(short[] probs, int index) throws IOException {
        short s = probs[index];
        int i = this.Range;
        int newBound = (i >>> 11) * s;
        int i2 = this.Code;
        if ((i2 ^ IntCompanionObject.MIN_VALUE) < (Integer.MIN_VALUE ^ newBound)) {
            this.Range = newBound;
            probs[index] = (short) (((2048 - s) >>> 5) + s);
            if ((this.Range & kTopMask) == 0) {
                this.Code = (i2 << 8) | this.Stream.read();
                this.Range <<= 8;
                return 0;
            }
            return 0;
        }
        this.Range = i - newBound;
        this.Code = i2 - newBound;
        probs[index] = (short) (s - (s >>> 5));
        if ((this.Range & kTopMask) == 0) {
            this.Code = (this.Code << 8) | this.Stream.read();
            this.Range <<= 8;
            return 1;
        }
        return 1;
    }

    public static void InitBitModels(short[] probs) {
        for (int i = 0; i < probs.length; i++) {
            probs[i] = 1024;
        }
    }
}