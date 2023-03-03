package kotlin.collections;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.UByteArray;
import kotlin.UIntArray;
import kotlin.ULongArray;
import kotlin.UShortArray;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Arrays.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000H\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a1\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0001¢\u0006\u0004\b\u0005\u0010\u0006\u001a!\u0010\u0007\u001a\u00020\b\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0003H\u0001¢\u0006\u0004\b\t\u0010\n\u001a?\u0010\u000b\u001a\u00020\f\"\u0004\b\u0000\u0010\u0002*\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00032\n\u0010\r\u001a\u00060\u000ej\u0002`\u000f2\u0010\u0010\u0010\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00030\u0011H\u0002¢\u0006\u0004\b\u0012\u0010\u0013\u001a+\u0010\u0014\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0015\"\u0004\b\u0000\u0010\u0002*\u0012\u0012\u000e\b\u0001\u0012\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u00030\u0003¢\u0006\u0002\u0010\u0016\u001a8\u0010\u0017\u001a\u0002H\u0018\"\u0010\b\u0000\u0010\u0019*\u0006\u0012\u0002\b\u00030\u0003*\u0002H\u0018\"\u0004\b\u0001\u0010\u0018*\u0002H\u00192\f\u0010\u001a\u001a\b\u0012\u0004\u0012\u0002H\u00180\u001bH\u0087\b¢\u0006\u0002\u0010\u001c\u001a)\u0010\u001d\u001a\u00020\u0001*\b\u0012\u0002\b\u0003\u0018\u00010\u0003H\u0087\b\u0082\u0002\u000e\n\f\b\u0000\u0012\u0002\u0018\u0001\u001a\u0004\b\u0003\u0010\u0000¢\u0006\u0002\u0010\u001e\u001aG\u0010\u001f\u001a\u001a\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00020\u0015\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00180\u00150 \"\u0004\b\u0000\u0010\u0002\"\u0004\b\u0001\u0010\u0018*\u0016\u0012\u0012\b\u0001\u0012\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00180 0\u0003¢\u0006\u0002\u0010!¨\u0006\""}, d2 = {"contentDeepEqualsImpl", BuildConfig.FLAVOR, "T", BuildConfig.FLAVOR, "other", "contentDeepEquals", "([Ljava/lang/Object;[Ljava/lang/Object;)Z", "contentDeepToStringImpl", BuildConfig.FLAVOR, "contentDeepToString", "([Ljava/lang/Object;)Ljava/lang/String;", "contentDeepToStringInternal", BuildConfig.FLAVOR, "result", "Ljava/lang/StringBuilder;", "Lkotlin/text/StringBuilder;", "processed", BuildConfig.FLAVOR, "contentDeepToStringInternal$ArraysKt__ArraysKt", "([Ljava/lang/Object;Ljava/lang/StringBuilder;Ljava/util/List;)V", "flatten", BuildConfig.FLAVOR, "([[Ljava/lang/Object;)Ljava/util/List;", "ifEmpty", "R", "C", "defaultValue", "Lkotlin/Function0;", "([Ljava/lang/Object;Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "isNullOrEmpty", "([Ljava/lang/Object;)Z", "unzip", "Lkotlin/Pair;", "([Lkotlin/Pair;)Lkotlin/Pair;", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/collections/ArraysKt")
/* loaded from: classes.dex */
public class ArraysKt__ArraysKt extends ArraysKt__ArraysJVMKt {
    public static final <T> List<T> flatten(T[][] flatten) {
        Intrinsics.checkParameterIsNotNull(flatten, "$this$flatten");
        T[][] $this$sumBy$iv = flatten;
        int sum$iv = 0;
        for (Object[] element$iv : $this$sumBy$iv) {
            Object[] it = element$iv;
            sum$iv += it.length;
        }
        ArrayList result = new ArrayList(sum$iv);
        for (T[] tArr : flatten) {
            CollectionsKt.addAll(result, tArr);
        }
        return result;
    }

    public static final <T, R> Pair<List<T>, List<R>> unzip(Pair<? extends T, ? extends R>[] unzip) {
        Intrinsics.checkParameterIsNotNull(unzip, "$this$unzip");
        ArrayList listT = new ArrayList(unzip.length);
        ArrayList listR = new ArrayList(unzip.length);
        for (Pair<? extends T, ? extends R> pair : unzip) {
            listT.add(pair.getFirst());
            listR.add(pair.getSecond());
        }
        return TuplesKt.to(listT, listR);
    }

    private static final boolean isNullOrEmpty(Object[] $this$isNullOrEmpty) {
        if ($this$isNullOrEmpty != null) {
            if (!($this$isNullOrEmpty.length == 0)) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Incorrect types in method signature: <C:[Ljava/lang/Object;:TR;R:Ljava/lang/Object;>(TC;Lkotlin/jvm/functions/Function0<+TR;>;)TR; */
    private static final Object ifEmpty(Object[] $this$ifEmpty, Function0 defaultValue) {
        return $this$ifEmpty.length == 0 ? defaultValue.invoke() : $this$ifEmpty;
    }

    public static final <T> boolean contentDeepEquals(T[] contentDeepEqualsImpl, T[] other) {
        Intrinsics.checkParameterIsNotNull(contentDeepEqualsImpl, "$this$contentDeepEqualsImpl");
        Intrinsics.checkParameterIsNotNull(other, "other");
        if (contentDeepEqualsImpl == other) {
            return true;
        }
        if (contentDeepEqualsImpl.length != other.length) {
            return false;
        }
        int length = contentDeepEqualsImpl.length;
        for (int i = 0; i < length; i++) {
            T t = contentDeepEqualsImpl[i];
            T t2 = other[i];
            if (t != t2) {
                if (t == null || t2 == null) {
                    return false;
                }
                if ((t instanceof Object[]) && (t2 instanceof Object[])) {
                    if (!ArraysKt.contentDeepEquals((Object[]) t, (Object[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof byte[]) && (t2 instanceof byte[])) {
                    if (!Arrays.equals((byte[]) t, (byte[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof short[]) && (t2 instanceof short[])) {
                    if (!Arrays.equals((short[]) t, (short[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof int[]) && (t2 instanceof int[])) {
                    if (!Arrays.equals((int[]) t, (int[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof long[]) && (t2 instanceof long[])) {
                    if (!Arrays.equals((long[]) t, (long[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof float[]) && (t2 instanceof float[])) {
                    if (!Arrays.equals((float[]) t, (float[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof double[]) && (t2 instanceof double[])) {
                    if (!Arrays.equals((double[]) t, (double[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof char[]) && (t2 instanceof char[])) {
                    if (!Arrays.equals((char[]) t, (char[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof boolean[]) && (t2 instanceof boolean[])) {
                    if (!Arrays.equals((boolean[]) t, (boolean[]) t2)) {
                        return false;
                    }
                } else if ((t instanceof UByteArray) && (t2 instanceof UByteArray)) {
                    if (!kotlin.collections.unsigned.UArraysKt.m399contentEqualskdPth3s(((UByteArray) t).m79unboximpl(), ((UByteArray) t2).m79unboximpl())) {
                        return false;
                    }
                } else if ((t instanceof UShortArray) && (t2 instanceof UShortArray)) {
                    if (!kotlin.collections.unsigned.UArraysKt.m400contentEqualsmazbYpA(((UShortArray) t).m284unboximpl(), ((UShortArray) t2).m284unboximpl())) {
                        return false;
                    }
                } else if ((t instanceof UIntArray) && (t2 instanceof UIntArray)) {
                    if (!kotlin.collections.unsigned.UArraysKt.m398contentEqualsctEhBpI(((UIntArray) t).m148unboximpl(), ((UIntArray) t2).m148unboximpl())) {
                        return false;
                    }
                } else if ((t instanceof ULongArray) && (t2 instanceof ULongArray)) {
                    if (!kotlin.collections.unsigned.UArraysKt.m401contentEqualsus8wMrg(((ULongArray) t).m217unboximpl(), ((ULongArray) t2).m217unboximpl())) {
                        return false;
                    }
                } else if (!Intrinsics.areEqual(t, t2)) {
                    return false;
                }
            }
        }
        return true;
    }

    public static final <T> String contentDeepToString(T[] contentDeepToStringImpl) {
        Intrinsics.checkParameterIsNotNull(contentDeepToStringImpl, "$this$contentDeepToStringImpl");
        int length = (RangesKt.coerceAtMost(contentDeepToStringImpl.length, 429496729) * 5) + 2;
        StringBuilder $this$buildString = new StringBuilder(length);
        contentDeepToStringInternal$ArraysKt__ArraysKt(contentDeepToStringImpl, $this$buildString, new ArrayList());
        String sb = $this$buildString.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb, "StringBuilder(capacity).…builderAction).toString()");
        return sb;
    }

    private static final <T> void contentDeepToStringInternal$ArraysKt__ArraysKt(T[] tArr, StringBuilder result, List<Object[]> list) {
        if (list.contains(tArr)) {
            result.append("[...]");
            return;
        }
        list.add(tArr);
        result.append('[');
        int length = tArr.length;
        for (int i = 0; i < length; i++) {
            if (i != 0) {
                result.append(", ");
            }
            T t = tArr[i];
            if (t == null) {
                result.append("null");
            } else if (t instanceof Object[]) {
                contentDeepToStringInternal$ArraysKt__ArraysKt((Object[]) t, result, list);
            } else if (t instanceof byte[]) {
                String arrays = Arrays.toString((byte[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
                result.append(arrays);
            } else if (t instanceof short[]) {
                String arrays2 = Arrays.toString((short[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays2, "java.util.Arrays.toString(this)");
                result.append(arrays2);
            } else if (t instanceof int[]) {
                String arrays3 = Arrays.toString((int[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays3, "java.util.Arrays.toString(this)");
                result.append(arrays3);
            } else if (t instanceof long[]) {
                String arrays4 = Arrays.toString((long[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays4, "java.util.Arrays.toString(this)");
                result.append(arrays4);
            } else if (t instanceof float[]) {
                String arrays5 = Arrays.toString((float[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays5, "java.util.Arrays.toString(this)");
                result.append(arrays5);
            } else if (t instanceof double[]) {
                String arrays6 = Arrays.toString((double[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays6, "java.util.Arrays.toString(this)");
                result.append(arrays6);
            } else if (t instanceof char[]) {
                String arrays7 = Arrays.toString((char[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays7, "java.util.Arrays.toString(this)");
                result.append(arrays7);
            } else if (t instanceof boolean[]) {
                String arrays8 = Arrays.toString((boolean[]) t);
                Intrinsics.checkExpressionValueIsNotNull(arrays8, "java.util.Arrays.toString(this)");
                result.append(arrays8);
            } else if (t instanceof UByteArray) {
                result.append(kotlin.collections.unsigned.UArraysKt.m407contentToStringGBYM_sE(((UByteArray) t).m79unboximpl()));
            } else if (t instanceof UShortArray) {
                result.append(kotlin.collections.unsigned.UArraysKt.m409contentToStringrL5Bavg(((UShortArray) t).m284unboximpl()));
            } else if (t instanceof UIntArray) {
                result.append(kotlin.collections.unsigned.UArraysKt.m406contentToStringajY9A(((UIntArray) t).m148unboximpl()));
            } else if (t instanceof ULongArray) {
                result.append(kotlin.collections.unsigned.UArraysKt.m408contentToStringQwZRm1k(((ULongArray) t).m217unboximpl()));
            } else {
                result.append(t.toString());
            }
        }
        result.append(']');
        list.remove(CollectionsKt.getLastIndex(list));
    }
}