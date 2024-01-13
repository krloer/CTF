package kotlin;

import kotlin.jvm.functions.Function1;
import s2g.project.game.BuildConfig;

/* compiled from: UShortArray.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001a\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u001a-\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0012\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00060\u0005H\u0087\bø\u0001\u0000¢\u0006\u0002\u0010\u0007\u001a\u001f\u0010\b\u001a\u00020\u00012\n\u0010\t\u001a\u00020\u0001\"\u00020\u0006H\u0087\bø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000b\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\f"}, d2 = {"UShortArray", "Lkotlin/UShortArray;", "size", BuildConfig.FLAVOR, "init", "Lkotlin/Function1;", "Lkotlin/UShort;", "(ILkotlin/jvm/functions/Function1;)[S", "ushortArrayOf", "elements", "ushortArrayOf-rL5Bavg", "([S)[S", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class UShortArrayKt {
    private static final short[] UShortArray(int size, Function1<? super Integer, UShort> function1) {
        short[] sArr = new short[size];
        for (int i = 0; i < size; i++) {
            int index = i;
            sArr[i] = function1.invoke(Integer.valueOf(index)).m267unboximpl();
        }
        return UShortArray.m270constructorimpl(sArr);
    }

    /* renamed from: ushortArrayOf-rL5Bavg  reason: not valid java name */
    private static final short[] m285ushortArrayOfrL5Bavg(short... elements) {
        return elements;
    }
}