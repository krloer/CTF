package com.badlogic.gdx.utils;

import java.util.Arrays;

/* loaded from: classes.dex */
public class Bits {
    long[] bits = {0};

    public Bits() {
    }

    public Bits(int nbits) {
        checkCapacity(nbits >>> 6);
    }

    public boolean get(int index) {
        int word = index >>> 6;
        long[] jArr = this.bits;
        if (word >= jArr.length) {
            return false;
        }
        return ((1 << (index & 63)) & jArr[word]) != 0;
    }

    public boolean getAndClear(int index) {
        int word = index >>> 6;
        long[] jArr = this.bits;
        if (word >= jArr.length) {
            return false;
        }
        long oldBits = jArr[word];
        jArr[word] = jArr[word] & ((1 << (index & 63)) ^ (-1));
        return jArr[word] != oldBits;
    }

    public boolean getAndSet(int index) {
        int word = index >>> 6;
        checkCapacity(word);
        long[] jArr = this.bits;
        long oldBits = jArr[word];
        jArr[word] = jArr[word] | (1 << (index & 63));
        return jArr[word] == oldBits;
    }

    public void set(int index) {
        int word = index >>> 6;
        checkCapacity(word);
        long[] jArr = this.bits;
        jArr[word] = jArr[word] | (1 << (index & 63));
    }

    public void flip(int index) {
        int word = index >>> 6;
        checkCapacity(word);
        long[] jArr = this.bits;
        jArr[word] = jArr[word] ^ (1 << (index & 63));
    }

    private void checkCapacity(int len) {
        long[] jArr = this.bits;
        if (len >= jArr.length) {
            long[] newBits = new long[len + 1];
            System.arraycopy(jArr, 0, newBits, 0, jArr.length);
            this.bits = newBits;
        }
    }

    public void clear(int index) {
        int word = index >>> 6;
        long[] jArr = this.bits;
        if (word >= jArr.length) {
            return;
        }
        jArr[word] = jArr[word] & ((1 << (index & 63)) ^ (-1));
    }

    public void clear() {
        Arrays.fill(this.bits, 0L);
    }

    public int numBits() {
        return this.bits.length << 6;
    }

    public int length() {
        long[] bits = this.bits;
        for (int word = bits.length - 1; word >= 0; word--) {
            long bitsAtWord = bits[word];
            if (bitsAtWord != 0) {
                for (int bit = 63; bit >= 0; bit--) {
                    if (((1 << (bit & 63)) & bitsAtWord) != 0) {
                        return (word << 6) + bit + 1;
                    }
                }
                continue;
            }
        }
        return 0;
    }

    public boolean notEmpty() {
        return !isEmpty();
    }

    public boolean isEmpty() {
        long[] bits = this.bits;
        int length = bits.length;
        for (int i = 0; i < length; i++) {
            if (bits[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public int nextSetBit(int fromIndex) {
        long[] bits = this.bits;
        int word = fromIndex >>> 6;
        int bitsLength = bits.length;
        if (word >= bitsLength) {
            return -1;
        }
        long bitsAtWord = bits[word];
        if (bitsAtWord != 0) {
            for (int i = fromIndex & 63; i < 64; i++) {
                if (((1 << (i & 63)) & bitsAtWord) != 0) {
                    return (word << 6) + i;
                }
            }
        }
        while (true) {
            word++;
            if (word >= bitsLength) {
                return -1;
            }
            if (word != 0) {
                long bitsAtWord2 = bits[word];
                if (bitsAtWord2 != 0) {
                    for (int i2 = 0; i2 < 64; i2++) {
                        if (((1 << (i2 & 63)) & bitsAtWord2) != 0) {
                            return (word << 6) + i2;
                        }
                    }
                    continue;
                } else {
                    continue;
                }
            }
        }
    }

    public int nextClearBit(int fromIndex) {
        long[] bits = this.bits;
        int word = fromIndex >>> 6;
        int bitsLength = bits.length;
        if (word >= bitsLength) {
            return bits.length << 6;
        }
        long bitsAtWord = bits[word];
        for (int i = fromIndex & 63; i < 64; i++) {
            if (((1 << (i & 63)) & bitsAtWord) == 0) {
                return (word << 6) + i;
            }
        }
        while (true) {
            word++;
            if (word < bitsLength) {
                if (word == 0) {
                    return word << 6;
                }
                long bitsAtWord2 = bits[word];
                for (int i2 = 0; i2 < 64; i2++) {
                    if (((1 << (i2 & 63)) & bitsAtWord2) == 0) {
                        return (word << 6) + i2;
                    }
                }
            } else {
                return bits.length << 6;
            }
        }
    }

    public void and(Bits other) {
        int commonWords = Math.min(this.bits.length, other.bits.length);
        for (int i = 0; commonWords > i; i++) {
            long[] jArr = this.bits;
            jArr[i] = jArr[i] & other.bits[i];
        }
        long[] jArr2 = this.bits;
        if (jArr2.length > commonWords) {
            int s = jArr2.length;
            for (int i2 = commonWords; s > i2; i2++) {
                this.bits[i2] = 0;
            }
        }
    }

    public void andNot(Bits other) {
        int j = this.bits.length;
        int k = other.bits.length;
        for (int i = 0; i < j && i < k; i++) {
            long[] jArr = this.bits;
            jArr[i] = jArr[i] & (other.bits[i] ^ (-1));
        }
    }

    public void or(Bits other) {
        int commonWords = Math.min(this.bits.length, other.bits.length);
        for (int i = 0; commonWords > i; i++) {
            long[] jArr = this.bits;
            jArr[i] = jArr[i] | other.bits[i];
        }
        long[] jArr2 = other.bits;
        if (commonWords < jArr2.length) {
            checkCapacity(jArr2.length);
            int s = other.bits.length;
            for (int i2 = commonWords; s > i2; i2++) {
                this.bits[i2] = other.bits[i2];
            }
        }
    }

    public void xor(Bits other) {
        int commonWords = Math.min(this.bits.length, other.bits.length);
        for (int i = 0; commonWords > i; i++) {
            long[] jArr = this.bits;
            jArr[i] = jArr[i] ^ other.bits[i];
        }
        long[] jArr2 = other.bits;
        if (commonWords < jArr2.length) {
            checkCapacity(jArr2.length);
            int s = other.bits.length;
            for (int i2 = commonWords; s > i2; i2++) {
                this.bits[i2] = other.bits[i2];
            }
        }
    }

    public boolean intersects(Bits other) {
        long[] bits = this.bits;
        long[] otherBits = other.bits;
        for (int i = Math.min(bits.length, otherBits.length) - 1; i >= 0; i--) {
            if ((bits[i] & otherBits[i]) != 0) {
                return true;
            }
        }
        return false;
    }

    public boolean containsAll(Bits other) {
        long[] bits = this.bits;
        long[] otherBits = other.bits;
        int otherBitsLength = otherBits.length;
        int bitsLength = bits.length;
        for (int i = bitsLength; i < otherBitsLength; i++) {
            if (otherBits[i] != 0) {
                return false;
            }
        }
        int i2 = Math.min(bitsLength, otherBitsLength);
        for (int i3 = i2 - 1; i3 >= 0; i3--) {
            if ((bits[i3] & otherBits[i3]) != otherBits[i3]) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        int word = length() >>> 6;
        int hash = 0;
        for (int i = 0; word >= i; i++) {
            long[] jArr = this.bits;
            hash = (hash * 127) + ((int) (jArr[i] ^ (jArr[i] >>> 32)));
        }
        return hash;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Bits other = (Bits) obj;
        long[] otherBits = other.bits;
        int commonWords = Math.min(this.bits.length, otherBits.length);
        for (int i = 0; commonWords > i; i++) {
            if (this.bits[i] != otherBits[i]) {
                return false;
            }
        }
        return this.bits.length == otherBits.length || length() == other.length();
    }
}