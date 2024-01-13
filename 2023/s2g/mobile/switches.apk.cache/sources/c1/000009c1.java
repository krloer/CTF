package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.internal.IntCompanionObject;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: StringNumberConversions.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000.\n\u0000\n\u0002\u0010\u0001\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0005\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0010\n\n\u0002\b\u0003\u001a\u0010\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0000\u001a\u0013\u0010\u0004\u001a\u0004\u0018\u00010\u0005*\u00020\u0003H\u0007¢\u0006\u0002\u0010\u0006\u001a\u001b\u0010\u0004\u001a\u0004\u0018\u00010\u0005*\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH\u0007¢\u0006\u0002\u0010\t\u001a\u0013\u0010\n\u001a\u0004\u0018\u00010\b*\u00020\u0003H\u0007¢\u0006\u0002\u0010\u000b\u001a\u001b\u0010\n\u001a\u0004\u0018\u00010\b*\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH\u0007¢\u0006\u0002\u0010\f\u001a\u0013\u0010\r\u001a\u0004\u0018\u00010\u000e*\u00020\u0003H\u0007¢\u0006\u0002\u0010\u000f\u001a\u001b\u0010\r\u001a\u0004\u0018\u00010\u000e*\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH\u0007¢\u0006\u0002\u0010\u0010\u001a\u0013\u0010\u0011\u001a\u0004\u0018\u00010\u0012*\u00020\u0003H\u0007¢\u0006\u0002\u0010\u0013\u001a\u001b\u0010\u0011\u001a\u0004\u0018\u00010\u0012*\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH\u0007¢\u0006\u0002\u0010\u0014¨\u0006\u0015"}, d2 = {"numberFormatError", BuildConfig.FLAVOR, "input", BuildConfig.FLAVOR, "toByteOrNull", BuildConfig.FLAVOR, "(Ljava/lang/String;)Ljava/lang/Byte;", "radix", BuildConfig.FLAVOR, "(Ljava/lang/String;I)Ljava/lang/Byte;", "toIntOrNull", "(Ljava/lang/String;)Ljava/lang/Integer;", "(Ljava/lang/String;I)Ljava/lang/Integer;", "toLongOrNull", BuildConfig.FLAVOR, "(Ljava/lang/String;)Ljava/lang/Long;", "(Ljava/lang/String;I)Ljava/lang/Long;", "toShortOrNull", BuildConfig.FLAVOR, "(Ljava/lang/String;)Ljava/lang/Short;", "(Ljava/lang/String;I)Ljava/lang/Short;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/text/StringsKt")
/* loaded from: classes.dex */
class StringsKt__StringNumberConversionsKt extends StringsKt__StringNumberConversionsJVMKt {
    public static final Byte toByteOrNull(String toByteOrNull) {
        Intrinsics.checkParameterIsNotNull(toByteOrNull, "$this$toByteOrNull");
        return StringsKt.toByteOrNull(toByteOrNull, 10);
    }

    public static final Byte toByteOrNull(String toByteOrNull, int radix) {
        int intValue;
        Intrinsics.checkParameterIsNotNull(toByteOrNull, "$this$toByteOrNull");
        Integer intOrNull = StringsKt.toIntOrNull(toByteOrNull, radix);
        if (intOrNull == null || (intValue = intOrNull.intValue()) < -128 || intValue > 127) {
            return null;
        }
        return Byte.valueOf((byte) intValue);
    }

    public static final Short toShortOrNull(String toShortOrNull) {
        Intrinsics.checkParameterIsNotNull(toShortOrNull, "$this$toShortOrNull");
        return StringsKt.toShortOrNull(toShortOrNull, 10);
    }

    public static final Short toShortOrNull(String toShortOrNull, int radix) {
        int intValue;
        Intrinsics.checkParameterIsNotNull(toShortOrNull, "$this$toShortOrNull");
        Integer intOrNull = StringsKt.toIntOrNull(toShortOrNull, radix);
        if (intOrNull == null || (intValue = intOrNull.intValue()) < -32768 || intValue > 32767) {
            return null;
        }
        return Short.valueOf((short) intValue);
    }

    public static final Integer toIntOrNull(String toIntOrNull) {
        Intrinsics.checkParameterIsNotNull(toIntOrNull, "$this$toIntOrNull");
        return StringsKt.toIntOrNull(toIntOrNull, 10);
    }

    public static final Integer toIntOrNull(String toIntOrNull, int radix) {
        int start;
        boolean isNegative;
        int limit;
        int result;
        Intrinsics.checkParameterIsNotNull(toIntOrNull, "$this$toIntOrNull");
        CharsKt.checkRadix(radix);
        int length = toIntOrNull.length();
        if (length == 0) {
            return null;
        }
        char firstChar = toIntOrNull.charAt(0);
        if (firstChar < '0') {
            if (length == 1) {
                return null;
            }
            start = 1;
            if (firstChar == '-') {
                isNegative = true;
                limit = IntCompanionObject.MIN_VALUE;
            } else if (firstChar != '+') {
                return null;
            } else {
                isNegative = false;
                limit = -2147483647;
            }
        } else {
            start = 0;
            isNegative = false;
            limit = -2147483647;
        }
        int limitBeforeMul = limit / radix;
        int result2 = 0;
        int i = length - 1;
        if (start <= i) {
            int i2 = start;
            while (true) {
                int digit = CharsKt.digitOf(toIntOrNull.charAt(i2), radix);
                if (digit < 0 || result2 < limitBeforeMul || (result = result2 * radix) < limit + digit) {
                    return null;
                }
                result2 = result - digit;
                if (i2 == i) {
                    break;
                }
                i2++;
            }
        }
        return isNegative ? Integer.valueOf(result2) : Integer.valueOf(-result2);
    }

    public static final Long toLongOrNull(String toLongOrNull) {
        Intrinsics.checkParameterIsNotNull(toLongOrNull, "$this$toLongOrNull");
        return StringsKt.toLongOrNull(toLongOrNull, 10);
    }

    public static final Long toLongOrNull(String toLongOrNull, int radix) {
        int start;
        boolean isNegative;
        long limit;
        Intrinsics.checkParameterIsNotNull(toLongOrNull, "$this$toLongOrNull");
        CharsKt.checkRadix(radix);
        int length = toLongOrNull.length();
        Long l = null;
        if (length == 0) {
            return null;
        }
        char firstChar = toLongOrNull.charAt(0);
        if (firstChar < '0') {
            if (length == 1) {
                return null;
            }
            start = 1;
            if (firstChar == '-') {
                isNegative = true;
                limit = Long.MIN_VALUE;
            } else if (firstChar != '+') {
                return null;
            } else {
                isNegative = false;
                limit = -9223372036854775807L;
            }
        } else {
            start = 0;
            isNegative = false;
            limit = -9223372036854775807L;
        }
        long limitBeforeMul = limit / radix;
        long result = 0;
        int i = length - 1;
        if (start <= i) {
            int i2 = start;
            while (true) {
                int digit = CharsKt.digitOf(toLongOrNull.charAt(i2), radix);
                if (digit < 0 || result < limitBeforeMul) {
                    return l;
                }
                int start2 = start;
                long result2 = result * radix;
                if (result2 >= digit + limit) {
                    result = result2 - digit;
                    if (i2 == i) {
                        break;
                    }
                    i2++;
                    start = start2;
                    l = null;
                } else {
                    return null;
                }
            }
        }
        return isNegative ? Long.valueOf(result) : Long.valueOf(-result);
    }

    public static final Void numberFormatError(String input) {
        Intrinsics.checkParameterIsNotNull(input, "input");
        throw new NumberFormatException("Invalid number format: '" + input + '\'');
    }
}