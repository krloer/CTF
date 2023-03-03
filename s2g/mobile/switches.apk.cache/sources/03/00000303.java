package com.badlogic.gdx.math;

import com.badlogic.gdx.graphics.GL20;
import java.util.Random;

/* loaded from: classes.dex */
public final class MathUtils {
    private static final double BIG_ENOUGH_CEIL = 16384.999999999996d;
    private static final double BIG_ENOUGH_FLOOR = 16384.0d;
    private static final int BIG_ENOUGH_INT = 16384;
    private static final double BIG_ENOUGH_ROUND = 16384.5d;
    private static final double CEIL = 0.9999999d;
    public static final float E = 2.7182817f;
    public static final float FLOAT_ROUNDING_ERROR = 1.0E-6f;
    public static final float HALF_PI = 1.5707964f;
    public static final float PI = 3.1415927f;
    public static final float PI2 = 6.2831855f;
    private static final int SIN_BITS = 14;
    private static final int SIN_COUNT = 16384;
    private static final int SIN_MASK = 16383;
    private static final float degFull = 360.0f;
    public static final float degRad = 0.017453292f;
    private static final float degToIndex = 45.511112f;
    public static final float degreesToRadians = 0.017453292f;
    public static final float nanoToSec = 1.0E-9f;
    public static final float radDeg = 57.295776f;
    private static final float radFull = 6.2831855f;
    private static final float radToIndex = 2607.5945f;
    public static final float radiansToDegrees = 57.295776f;
    public static Random random = new RandomXS128();

    private MathUtils() {
    }

    /* loaded from: classes.dex */
    private static class Sin {
        static final float[] table = new float[GL20.GL_COLOR_BUFFER_BIT];

        private Sin() {
        }

        static {
            for (int i = 0; i < 16384; i++) {
                table[i] = (float) Math.sin(((i + 0.5f) / 16384.0f) * 6.2831855f);
            }
            for (int i2 = 0; i2 < 360; i2 += 90) {
                table[((int) (i2 * MathUtils.degToIndex)) & MathUtils.SIN_MASK] = (float) Math.sin(i2 * 0.017453292f);
            }
        }
    }

    public static float sin(float radians) {
        return Sin.table[((int) (radToIndex * radians)) & SIN_MASK];
    }

    public static float cos(float radians) {
        return Sin.table[((int) ((1.5707964f + radians) * radToIndex)) & SIN_MASK];
    }

    public static float sinDeg(float degrees) {
        return Sin.table[((int) (degToIndex * degrees)) & SIN_MASK];
    }

    public static float cosDeg(float degrees) {
        return Sin.table[((int) ((90.0f + degrees) * degToIndex)) & SIN_MASK];
    }

    public static float atan2(float y, float x) {
        if (x == 0.0f) {
            if (y > 0.0f) {
                return 1.5707964f;
            }
            return y == 0.0f ? 0.0f : -1.5707964f;
        }
        float z = y / x;
        if (Math.abs(z) >= 1.0f) {
            float atan = 1.5707964f - (z / ((z * z) + 0.28f));
            return y < 0.0f ? atan - 3.1415927f : atan;
        }
        float atan2 = z / (((0.28f * z) * z) + 1.0f);
        if (x < 0.0f) {
            return (y < 0.0f ? -3.1415927f : 3.1415927f) + atan2;
        }
        return atan2;
    }

    public static float acos(float a) {
        float a2 = a * a;
        float a3 = a * a2;
        if (a >= 0.0f) {
            return ((float) Math.sqrt(1.0f - a)) * (((1.5707288f - (0.2121144f * a)) + (0.074261f * a2)) - (0.0187293f * a3));
        }
        return 3.1415927f - (((float) Math.sqrt(1.0f + a)) * ((((0.2121144f * a) + 1.5707288f) + (0.074261f * a2)) + (0.0187293f * a3)));
    }

    public static float asin(float a) {
        float a2 = a * a;
        float a3 = a * a2;
        if (a >= 0.0f) {
            return 1.5707964f - (((float) Math.sqrt(1.0f - a)) * (((1.5707288f - (0.2121144f * a)) + (0.074261f * a2)) - (0.0187293f * a3)));
        }
        return (((float) Math.sqrt(1.0f + a)) * ((((0.2121144f * a) + 1.5707288f) + (0.074261f * a2)) + (0.0187293f * a3))) - 1.5707964f;
    }

    public static int random(int range) {
        return random.nextInt(range + 1);
    }

    public static int random(int start, int end) {
        return random.nextInt((end - start) + 1) + start;
    }

    public static long random(long range) {
        return random(0L, range);
    }

    public static long random(long start, long end) {
        long start2;
        long end2;
        long rand = random.nextLong();
        if (end >= start) {
            start2 = start;
            end2 = end;
        } else {
            end2 = start;
            start2 = end;
        }
        long bound = (end2 - start2) + 1;
        long randLow = rand & 4294967295L;
        long boundLow = 4294967295L & bound;
        long randHigh = rand >>> 32;
        long boundHigh = bound >>> 32;
        return start2 + ((randHigh * boundLow) >>> 32) + ((randLow * boundHigh) >>> 32) + (randHigh * boundHigh);
    }

    public static boolean randomBoolean() {
        return random.nextBoolean();
    }

    public static boolean randomBoolean(float chance) {
        return random() < chance;
    }

    public static float random() {
        return random.nextFloat();
    }

    public static float random(float range) {
        return random.nextFloat() * range;
    }

    public static float random(float start, float end) {
        return (random.nextFloat() * (end - start)) + start;
    }

    public static int randomSign() {
        return (random.nextInt() >> 31) | 1;
    }

    public static float randomTriangular() {
        return random.nextFloat() - random.nextFloat();
    }

    public static float randomTriangular(float max) {
        return (random.nextFloat() - random.nextFloat()) * max;
    }

    public static float randomTriangular(float min, float max) {
        return randomTriangular(min, max, (min + max) * 0.5f);
    }

    public static float randomTriangular(float min, float max, float mode) {
        float u = random.nextFloat();
        float d = max - min;
        return u <= (mode - min) / d ? ((float) Math.sqrt(u * d * (mode - min))) + min : max - ((float) Math.sqrt(((1.0f - u) * d) * (max - mode)));
    }

    public static int nextPowerOfTwo(int value) {
        if (value == 0) {
            return 1;
        }
        int value2 = value - 1;
        int value3 = value2 | (value2 >> 1);
        int value4 = value3 | (value3 >> 2);
        int value5 = value4 | (value4 >> 4);
        int value6 = value5 | (value5 >> 8);
        return (value6 | (value6 >> 16)) + 1;
    }

    public static boolean isPowerOfTwo(int value) {
        return value != 0 && ((value + (-1)) & value) == 0;
    }

    public static short clamp(short value, short min, short max) {
        return value < min ? min : value > max ? max : value;
    }

    public static int clamp(int value, int min, int max) {
        return value < min ? min : value > max ? max : value;
    }

    public static long clamp(long value, long min, long max) {
        return value < min ? min : value > max ? max : value;
    }

    public static float clamp(float value, float min, float max) {
        return value < min ? min : value > max ? max : value;
    }

    public static double clamp(double value, double min, double max) {
        return value < min ? min : value > max ? max : value;
    }

    public static float lerp(float fromValue, float toValue, float progress) {
        return ((toValue - fromValue) * progress) + fromValue;
    }

    public static float norm(float rangeStart, float rangeEnd, float value) {
        return (value - rangeStart) / (rangeEnd - rangeStart);
    }

    public static float map(float inRangeStart, float inRangeEnd, float outRangeStart, float outRangeEnd, float value) {
        return (((value - inRangeStart) * (outRangeEnd - outRangeStart)) / (inRangeEnd - inRangeStart)) + outRangeStart;
    }

    public static float lerpAngle(float fromRadians, float toRadians, float progress) {
        float delta = ((((toRadians - fromRadians) + 6.2831855f) + 3.1415927f) % 6.2831855f) - 3.1415927f;
        return (((delta * progress) + fromRadians) + 6.2831855f) % 6.2831855f;
    }

    public static float lerpAngleDeg(float fromDegrees, float toDegrees, float progress) {
        float delta = ((((toDegrees - fromDegrees) + degFull) + 180.0f) % degFull) - 180.0f;
        return (((delta * progress) + fromDegrees) + degFull) % degFull;
    }

    public static int floor(float value) {
        double d;
        Double.isNaN(value);
        return ((int) (d + BIG_ENOUGH_FLOOR)) - 16384;
    }

    public static int floorPositive(float value) {
        return (int) value;
    }

    public static int ceil(float value) {
        double d = value;
        Double.isNaN(d);
        return 16384 - ((int) (BIG_ENOUGH_FLOOR - d));
    }

    public static int ceilPositive(float value) {
        double d = value;
        Double.isNaN(d);
        return (int) (d + CEIL);
    }

    public static int round(float value) {
        double d;
        Double.isNaN(value);
        return ((int) (d + BIG_ENOUGH_ROUND)) - 16384;
    }

    public static int roundPositive(float value) {
        return (int) (0.5f + value);
    }

    public static boolean isZero(float value) {
        return Math.abs(value) <= 1.0E-6f;
    }

    public static boolean isZero(float value, float tolerance) {
        return Math.abs(value) <= tolerance;
    }

    public static boolean isEqual(float a, float b) {
        return Math.abs(a - b) <= 1.0E-6f;
    }

    public static boolean isEqual(float a, float b, float tolerance) {
        return Math.abs(a - b) <= tolerance;
    }

    public static float log(float a, float value) {
        return (float) (Math.log(value) / Math.log(a));
    }

    public static float log2(float value) {
        return log(2.0f, value);
    }
}