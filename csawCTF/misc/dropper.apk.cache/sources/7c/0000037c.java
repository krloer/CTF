package v;

import android.graphics.Color;

/* loaded from: classes.dex */
public final class a {

    /* renamed from: a  reason: collision with root package name */
    public final float f3231a;

    /* renamed from: b  reason: collision with root package name */
    public final float f3232b;

    /* renamed from: c  reason: collision with root package name */
    public final float f3233c;

    /* renamed from: d  reason: collision with root package name */
    public final float f3234d;

    /* renamed from: e  reason: collision with root package name */
    public final float f3235e;

    /* renamed from: f  reason: collision with root package name */
    public final float f3236f;

    public a(float f2, float f3, float f4, float f5, float f6, float f7) {
        this.f3231a = f2;
        this.f3232b = f3;
        this.f3233c = f4;
        this.f3234d = f5;
        this.f3235e = f6;
        this.f3236f = f7;
    }

    public static a a(int i2) {
        float pow;
        k kVar = k.f3258k;
        float b02 = androidx.emoji2.text.i.b0(Color.red(i2));
        float b03 = androidx.emoji2.text.i.b0(Color.green(i2));
        float b04 = androidx.emoji2.text.i.b0(Color.blue(i2));
        float[][] fArr = androidx.emoji2.text.i.f666p;
        float[] fArr2 = fArr[0];
        float f2 = (fArr2[2] * b04) + (fArr2[1] * b03) + (fArr2[0] * b02);
        float[] fArr3 = fArr[1];
        float f3 = (fArr3[2] * b04) + (fArr3[1] * b03) + (fArr3[0] * b02);
        float[] fArr4 = fArr[2];
        float f4 = (b04 * fArr4[2]) + (b03 * fArr4[1]) + (b02 * fArr4[0]);
        float[][] fArr5 = androidx.emoji2.text.i.f663m;
        float[] fArr6 = fArr5[0];
        float f5 = (fArr6[2] * f4) + (fArr6[1] * f3) + (fArr6[0] * f2);
        float[] fArr7 = fArr5[1];
        float f6 = fArr7[1] * f3;
        float f7 = fArr7[2] * f4;
        float[] fArr8 = fArr5[2];
        float f8 = f2 * fArr8[0];
        float f9 = f4 * fArr8[2];
        float[] fArr9 = kVar.f3265g;
        float f10 = fArr9[0] * f5;
        float f11 = fArr9[1] * (f7 + f6 + (fArr7[0] * f2));
        float f12 = fArr9[2] * (f9 + (f3 * fArr8[1]) + f8);
        float abs = Math.abs(f10);
        float f13 = kVar.f3266h;
        float pow2 = (float) Math.pow((abs * f13) / 100.0d, 0.42d);
        float pow3 = (float) Math.pow((Math.abs(f11) * f13) / 100.0d, 0.42d);
        float pow4 = (float) Math.pow((Math.abs(f12) * f13) / 100.0d, 0.42d);
        float signum = ((Math.signum(f10) * 400.0f) * pow2) / (pow2 + 27.13f);
        float signum2 = ((Math.signum(f11) * 400.0f) * pow3) / (pow3 + 27.13f);
        float signum3 = ((Math.signum(f12) * 400.0f) * pow4) / (pow4 + 27.13f);
        double d2 = signum3;
        float f14 = ((float) (((signum2 * (-12.0d)) + (signum * 11.0d)) + d2)) / 11.0f;
        float f15 = ((float) ((signum + signum2) - (d2 * 2.0d))) / 9.0f;
        float f16 = signum2 * 20.0f;
        float f17 = ((21.0f * signum3) + ((signum * 20.0f) + f16)) / 20.0f;
        float f18 = (((signum * 40.0f) + f16) + signum3) / 20.0f;
        float atan2 = (((float) Math.atan2(f15, f14)) * 180.0f) / 3.1415927f;
        if (atan2 < 0.0f) {
            atan2 += 360.0f;
        } else if (atan2 >= 360.0f) {
            atan2 -= 360.0f;
        }
        float f19 = atan2;
        float f20 = (3.1415927f * f19) / 180.0f;
        float f21 = f18 * kVar.f3260b;
        float f22 = kVar.f3259a;
        double d3 = f21 / f22;
        float f23 = kVar.f3268j;
        float f24 = kVar.f3262d;
        float pow5 = ((float) Math.pow(d3, f23 * f24)) * 100.0f;
        Math.sqrt(pow5 / 100.0f);
        float f25 = f22 + 4.0f;
        float pow6 = ((float) Math.pow(1.64d - Math.pow(0.29d, kVar.f3264f), 0.73d)) * ((float) Math.pow((((((((float) (Math.cos((((((double) f19) < 20.14d ? 360.0f + f19 : f19) * 3.141592653589793d) / 180.0d) + 2.0d) + 3.8d)) * 0.25f) * 3846.1538f) * kVar.f3263e) * kVar.f3261c) * ((float) Math.sqrt((f15 * f15) + (f14 * f14)))) / (f17 + 0.305f), 0.9d)) * ((float) Math.sqrt(pow5 / 100.0d));
        Math.sqrt((pow * f24) / f25);
        float f26 = (1.7f * pow5) / ((0.007f * pow5) + 1.0f);
        float log = ((float) Math.log((kVar.f3267i * pow6 * 0.0228f) + 1.0f)) * 43.85965f;
        double d4 = f20;
        return new a(f19, pow6, pow5, f26, log * ((float) Math.cos(d4)), log * ((float) Math.sin(d4)));
    }

    public static a b(float f2, float f3, float f4) {
        k kVar;
        double d2;
        float f5 = k.f3258k.f3262d;
        Math.sqrt(f2 / 100.0d);
        Math.sqrt(((f3 / ((float) Math.sqrt(d2))) * kVar.f3262d) / (kVar.f3259a + 4.0f));
        float f6 = (1.7f * f2) / ((0.007f * f2) + 1.0f);
        float log = ((float) Math.log((kVar.f3267i * f3 * 0.0228d) + 1.0d)) * 43.85965f;
        double d3 = (3.1415927f * f4) / 180.0f;
        return new a(f4, f3, f2, f6, log * ((float) Math.cos(d3)), log * ((float) Math.sin(d3)));
    }

    public final int c(k kVar) {
        float f2;
        float[] fArr;
        float f3 = this.f3232b;
        int i2 = (f3 > 0.0d ? 1 : (f3 == 0.0d ? 0 : -1));
        float f4 = this.f3233c;
        if (i2 != 0) {
            double d2 = f4;
            if (d2 != 0.0d) {
                f2 = f3 / ((float) Math.sqrt(d2 / 100.0d));
                float pow = (float) Math.pow(f2 / Math.pow(1.64d - Math.pow(0.29d, kVar.f3264f), 0.73d), 1.1111111111111112d);
                double d3 = (this.f3231a * 3.1415927f) / 180.0f;
                float pow2 = kVar.f3259a * ((float) Math.pow(f4 / 100.0d, (1.0d / kVar.f3262d) / kVar.f3268j));
                float cos = ((float) (Math.cos(2.0d + d3) + 3.8d)) * 0.25f * 3846.1538f * kVar.f3263e * kVar.f3261c;
                float f5 = pow2 / kVar.f3260b;
                float sin = (float) Math.sin(d3);
                float cos2 = (float) Math.cos(d3);
                float f6 = (((0.305f + f5) * 23.0f) * pow) / (((pow * 108.0f) * sin) + (((11.0f * pow) * cos2) + (cos * 23.0f)));
                float f7 = cos2 * f6;
                float f8 = f6 * sin;
                float f9 = f5 * 460.0f;
                float f10 = ((288.0f * f8) + ((451.0f * f7) + f9)) / 1403.0f;
                float f11 = ((f9 - (891.0f * f7)) - (261.0f * f8)) / 1403.0f;
                float f12 = ((f9 - (f7 * 220.0f)) - (f8 * 6300.0f)) / 1403.0f;
                float max = (float) Math.max(0.0d, (Math.abs(f10) * 27.13d) / (400.0d - Math.abs(f10)));
                float signum = Math.signum(f10);
                float f13 = 100.0f / kVar.f3266h;
                float pow3 = signum * f13 * ((float) Math.pow(max, 2.380952380952381d));
                float signum2 = Math.signum(f11) * f13 * ((float) Math.pow((float) Math.max(0.0d, (Math.abs(f11) * 27.13d) / (400.0d - Math.abs(f11))), 2.380952380952381d));
                float signum3 = Math.signum(f12) * f13 * ((float) Math.pow((float) Math.max(0.0d, (Math.abs(f12) * 27.13d) / (400.0d - Math.abs(f12))), 2.380952380952381d));
                float[] fArr2 = kVar.f3265g;
                float f14 = pow3 / fArr2[0];
                float f15 = signum2 / fArr2[1];
                float f16 = signum3 / fArr2[2];
                float[][] fArr3 = androidx.emoji2.text.i.f664n;
                float[] fArr4 = fArr3[0];
                float f17 = (fArr4[2] * f16) + (fArr4[1] * f15) + (fArr4[0] * f14);
                float[] fArr5 = fArr3[1];
                float f18 = fArr5[1] * f15;
                float f19 = fArr5[2] * f16;
                float f20 = f14 * fArr3[2][0];
                return w.a.a(f17, f19 + f18 + (fArr5[0] * f14), (f16 * fArr[2]) + (f15 * fArr[1]) + f20);
            }
        }
        f2 = 0.0f;
        float pow4 = (float) Math.pow(f2 / Math.pow(1.64d - Math.pow(0.29d, kVar.f3264f), 0.73d), 1.1111111111111112d);
        double d32 = (this.f3231a * 3.1415927f) / 180.0f;
        float pow22 = kVar.f3259a * ((float) Math.pow(f4 / 100.0d, (1.0d / kVar.f3262d) / kVar.f3268j));
        float cos3 = ((float) (Math.cos(2.0d + d32) + 3.8d)) * 0.25f * 3846.1538f * kVar.f3263e * kVar.f3261c;
        float f52 = pow22 / kVar.f3260b;
        float sin2 = (float) Math.sin(d32);
        float cos22 = (float) Math.cos(d32);
        float f62 = (((0.305f + f52) * 23.0f) * pow4) / (((pow4 * 108.0f) * sin2) + (((11.0f * pow4) * cos22) + (cos3 * 23.0f)));
        float f72 = cos22 * f62;
        float f82 = f62 * sin2;
        float f92 = f52 * 460.0f;
        float f102 = ((288.0f * f82) + ((451.0f * f72) + f92)) / 1403.0f;
        float f112 = ((f92 - (891.0f * f72)) - (261.0f * f82)) / 1403.0f;
        float f122 = ((f92 - (f72 * 220.0f)) - (f82 * 6300.0f)) / 1403.0f;
        float max2 = (float) Math.max(0.0d, (Math.abs(f102) * 27.13d) / (400.0d - Math.abs(f102)));
        float signum4 = Math.signum(f102);
        float f132 = 100.0f / kVar.f3266h;
        float pow32 = signum4 * f132 * ((float) Math.pow(max2, 2.380952380952381d));
        float signum22 = Math.signum(f112) * f132 * ((float) Math.pow((float) Math.max(0.0d, (Math.abs(f112) * 27.13d) / (400.0d - Math.abs(f112))), 2.380952380952381d));
        float signum32 = Math.signum(f122) * f132 * ((float) Math.pow((float) Math.max(0.0d, (Math.abs(f122) * 27.13d) / (400.0d - Math.abs(f122))), 2.380952380952381d));
        float[] fArr22 = kVar.f3265g;
        float f142 = pow32 / fArr22[0];
        float f152 = signum22 / fArr22[1];
        float f162 = signum32 / fArr22[2];
        float[][] fArr32 = androidx.emoji2.text.i.f664n;
        float[] fArr42 = fArr32[0];
        float f172 = (fArr42[2] * f162) + (fArr42[1] * f152) + (fArr42[0] * f142);
        float[] fArr52 = fArr32[1];
        float f182 = fArr52[1] * f152;
        float f192 = fArr52[2] * f162;
        float f202 = f142 * fArr32[2][0];
        return w.a.a(f172, f192 + f182 + (fArr52[0] * f142), (f162 * fArr[2]) + (f152 * fArr[1]) + f202);
    }
}