package com.badlogic.gdx.math;

import java.util.Random;

/* loaded from: classes.dex */
public class RandomXS128 extends Random {
    private static final double NORM_DOUBLE = 1.1102230246251565E-16d;
    private static final double NORM_FLOAT = 5.9604644775390625E-8d;
    private long seed0;
    private long seed1;

    public RandomXS128() {
        setSeed(new Random().nextLong());
    }

    public RandomXS128(long seed) {
        setSeed(seed);
    }

    public RandomXS128(long seed0, long seed1) {
        setState(seed0, seed1);
    }

    @Override // java.util.Random
    public long nextLong() {
        long s1 = this.seed0;
        long s0 = this.seed1;
        this.seed0 = s0;
        long s12 = s1 ^ (s1 << 23);
        long j = ((s12 ^ s0) ^ (s12 >>> 17)) ^ (s0 >>> 26);
        this.seed1 = j;
        return j + s0;
    }

    @Override // java.util.Random
    protected final int next(int bits) {
        return (int) (nextLong() & ((1 << bits) - 1));
    }

    @Override // java.util.Random
    public int nextInt() {
        return (int) nextLong();
    }

    @Override // java.util.Random
    public int nextInt(int n) {
        return (int) nextLong(n);
    }

    public long nextLong(long n) {
        long bits;
        long value;
        if (n > 0) {
            do {
                bits = nextLong() >>> 1;
                value = bits % n;
            } while ((bits - value) + (n - 1) < 0);
            return value;
        }
        throw new IllegalArgumentException("n must be positive");
    }

    @Override // java.util.Random
    public double nextDouble() {
        double nextLong = nextLong() >>> 11;
        Double.isNaN(nextLong);
        return nextLong * NORM_DOUBLE;
    }

    @Override // java.util.Random
    public float nextFloat() {
        double nextLong = nextLong() >>> 40;
        Double.isNaN(nextLong);
        return (float) (nextLong * NORM_FLOAT);
    }

    @Override // java.util.Random
    public boolean nextBoolean() {
        return (nextLong() & 1) != 0;
    }

    @Override // java.util.Random
    public void nextBytes(byte[] bytes) {
        int i = bytes.length;
        while (i != 0) {
            int n = i < 8 ? i : 8;
            long bits = nextLong();
            while (true) {
                int n2 = n - 1;
                if (n != 0) {
                    i--;
                    bytes[i] = (byte) bits;
                    bits >>= 8;
                    n = n2;
                }
            }
        }
    }

    @Override // java.util.Random
    public void setSeed(long seed) {
        long seed0 = murmurHash3(seed == 0 ? Long.MIN_VALUE : seed);
        setState(seed0, murmurHash3(seed0));
    }

    public void setState(long seed0, long seed1) {
        this.seed0 = seed0;
        this.seed1 = seed1;
    }

    public long getState(int seed) {
        return seed == 0 ? this.seed0 : this.seed1;
    }

    private static final long murmurHash3(long x) {
        long x2 = (x ^ (x >>> 33)) * (-49064778989728563L);
        long x3 = (x2 ^ (x2 >>> 33)) * (-4265267296055464877L);
        return x3 ^ (x3 >>> 33);
    }
}