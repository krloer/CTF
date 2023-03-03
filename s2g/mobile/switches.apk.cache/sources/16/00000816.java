package kotlin.coroutines.jvm.internal;

import kotlin.Metadata;
import s2g.project.game.BuildConfig;

/* compiled from: boxing.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000T\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0005\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0006\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\n\n\u0000\u001a\u0010\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0001\u001a\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0002\u001a\u00020\u0006H\u0001\u001a\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0002\u001a\u00020\tH\u0001\u001a\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0002\u001a\u00020\fH\u0001\u001a\u0010\u0010\r\u001a\u00020\u000e2\u0006\u0010\u0002\u001a\u00020\u000fH\u0001\u001a\u0010\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0002\u001a\u00020\u0012H\u0001\u001a\u0010\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0002\u001a\u00020\u0015H\u0001\u001a\u0010\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0002\u001a\u00020\u0018H\u0001¨\u0006\u0019"}, d2 = {"boxBoolean", "Ljava/lang/Boolean;", "primitive", BuildConfig.FLAVOR, "boxByte", "Ljava/lang/Byte;", BuildConfig.FLAVOR, "boxChar", "Ljava/lang/Character;", BuildConfig.FLAVOR, "boxDouble", "Ljava/lang/Double;", BuildConfig.FLAVOR, "boxFloat", "Ljava/lang/Float;", BuildConfig.FLAVOR, "boxInt", "Ljava/lang/Integer;", BuildConfig.FLAVOR, "boxLong", "Ljava/lang/Long;", BuildConfig.FLAVOR, "boxShort", "Ljava/lang/Short;", BuildConfig.FLAVOR, "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class Boxing {
    public static final Boolean boxBoolean(boolean primitive) {
        return Boolean.valueOf(primitive);
    }

    public static final Byte boxByte(byte primitive) {
        return Byte.valueOf(primitive);
    }

    public static final Short boxShort(short primitive) {
        return new Short(primitive);
    }

    public static final Integer boxInt(int primitive) {
        return new Integer(primitive);
    }

    public static final Long boxLong(long primitive) {
        return new Long(primitive);
    }

    public static final Float boxFloat(float primitive) {
        return new Float(primitive);
    }

    public static final Double boxDouble(double primitive) {
        return new Double(primitive);
    }

    public static final Character boxChar(char primitive) {
        return new Character(primitive);
    }
}