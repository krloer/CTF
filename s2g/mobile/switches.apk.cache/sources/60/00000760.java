package kotlin.collections;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import s2g.project.game.BuildConfig;

/* compiled from: ReversedViews.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0018\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010!\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\u001a\u001c\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0001\u001a#\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0003\"\u0004\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003H\u0007¢\u0006\u0002\b\u0004\u001a\u001d\u0010\u0005\u001a\u00020\u0006*\u0006\u0012\u0002\b\u00030\u00012\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0002\b\b\u001a\u001d\u0010\t\u001a\u00020\u0006*\u0006\u0012\u0002\b\u00030\u00012\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0002\b\n¨\u0006\u000b"}, d2 = {"asReversed", BuildConfig.FLAVOR, "T", BuildConfig.FLAVOR, "asReversedMutable", "reverseElementIndex", BuildConfig.FLAVOR, "index", "reverseElementIndex$CollectionsKt__ReversedViewsKt", "reversePositionIndex", "reversePositionIndex$CollectionsKt__ReversedViewsKt", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/collections/CollectionsKt")
/* loaded from: classes.dex */
class CollectionsKt__ReversedViewsKt extends CollectionsKt__MutableCollectionsKt {
    /* JADX INFO: Access modifiers changed from: private */
    public static final int reverseElementIndex$CollectionsKt__ReversedViewsKt(List<?> list, int index) {
        int lastIndex = CollectionsKt.getLastIndex(list);
        if (index < 0 || lastIndex < index) {
            throw new IndexOutOfBoundsException("Element index " + index + " must be in range [" + new IntRange(0, CollectionsKt.getLastIndex(list)) + "].");
        }
        return CollectionsKt.getLastIndex(list) - index;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int reversePositionIndex$CollectionsKt__ReversedViewsKt(List<?> list, int index) {
        int size = list.size();
        if (index < 0 || size < index) {
            throw new IndexOutOfBoundsException("Position index " + index + " must be in range [" + new IntRange(0, list.size()) + "].");
        }
        return list.size() - index;
    }

    public static final <T> List<T> asReversed(List<? extends T> asReversed) {
        Intrinsics.checkParameterIsNotNull(asReversed, "$this$asReversed");
        return new ReversedListReadOnly(asReversed);
    }

    public static final <T> List<T> asReversedMutable(List<T> asReversed) {
        Intrinsics.checkParameterIsNotNull(asReversed, "$this$asReversed");
        return new ReversedList(asReversed);
    }
}