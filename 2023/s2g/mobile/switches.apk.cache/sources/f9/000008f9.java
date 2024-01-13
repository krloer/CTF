package kotlin.random;

import kotlin.Metadata;
import kotlin.UByteArray;
import kotlin.UInt;
import kotlin.ULong;
import kotlin.UnsignedKt;
import kotlin.jvm.internal.IntCompanionObject;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.UIntRange;
import kotlin.ranges.ULongRange;
import s2g.project.game.BuildConfig;

/* compiled from: URandom.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000:\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\"\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003H\u0001ø\u0001\u0000¢\u0006\u0004\b\u0005\u0010\u0006\u001a\"\u0010\u0007\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u0004\u001a\u00020\bH\u0001ø\u0001\u0000¢\u0006\u0004\b\t\u0010\n\u001a\u001c\u0010\u000b\u001a\u00020\f*\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0007ø\u0001\u0000¢\u0006\u0002\u0010\u0010\u001a\u001e\u0010\u000b\u001a\u00020\f*\u00020\r2\u0006\u0010\u0011\u001a\u00020\fH\u0007ø\u0001\u0000¢\u0006\u0004\b\u0012\u0010\u0013\u001a2\u0010\u000b\u001a\u00020\f*\u00020\r2\u0006\u0010\u0011\u001a\u00020\f2\b\b\u0002\u0010\u0014\u001a\u00020\u000f2\b\b\u0002\u0010\u0015\u001a\u00020\u000fH\u0007ø\u0001\u0000¢\u0006\u0004\b\u0016\u0010\u0017\u001a\u0014\u0010\u0018\u001a\u00020\u0003*\u00020\rH\u0007ø\u0001\u0000¢\u0006\u0002\u0010\u0019\u001a\u001e\u0010\u0018\u001a\u00020\u0003*\u00020\r2\u0006\u0010\u0004\u001a\u00020\u0003H\u0007ø\u0001\u0000¢\u0006\u0004\b\u001a\u0010\u001b\u001a&\u0010\u0018\u001a\u00020\u0003*\u00020\r2\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003H\u0007ø\u0001\u0000¢\u0006\u0004\b\u001c\u0010\u001d\u001a\u001c\u0010\u0018\u001a\u00020\u0003*\u00020\r2\u0006\u0010\u001e\u001a\u00020\u001fH\u0007ø\u0001\u0000¢\u0006\u0002\u0010 \u001a\u0014\u0010!\u001a\u00020\b*\u00020\rH\u0007ø\u0001\u0000¢\u0006\u0002\u0010\"\u001a\u001e\u0010!\u001a\u00020\b*\u00020\r2\u0006\u0010\u0004\u001a\u00020\bH\u0007ø\u0001\u0000¢\u0006\u0004\b#\u0010$\u001a&\u0010!\u001a\u00020\b*\u00020\r2\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u0004\u001a\u00020\bH\u0007ø\u0001\u0000¢\u0006\u0004\b%\u0010&\u001a\u001c\u0010!\u001a\u00020\b*\u00020\r2\u0006\u0010\u001e\u001a\u00020'H\u0007ø\u0001\u0000¢\u0006\u0002\u0010(\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006)"}, d2 = {"checkUIntRangeBounds", BuildConfig.FLAVOR, "from", "Lkotlin/UInt;", "until", "checkUIntRangeBounds-J1ME1BU", "(II)V", "checkULongRangeBounds", "Lkotlin/ULong;", "checkULongRangeBounds-eb3DHEI", "(JJ)V", "nextUBytes", "Lkotlin/UByteArray;", "Lkotlin/random/Random;", "size", BuildConfig.FLAVOR, "(Lkotlin/random/Random;I)[B", "array", "nextUBytes-EVgfTAA", "(Lkotlin/random/Random;[B)[B", "fromIndex", "toIndex", "nextUBytes-Wvrt4B4", "(Lkotlin/random/Random;[BII)[B", "nextUInt", "(Lkotlin/random/Random;)I", "nextUInt-qCasIEU", "(Lkotlin/random/Random;I)I", "nextUInt-a8DCA5k", "(Lkotlin/random/Random;II)I", "range", "Lkotlin/ranges/UIntRange;", "(Lkotlin/random/Random;Lkotlin/ranges/UIntRange;)I", "nextULong", "(Lkotlin/random/Random;)J", "nextULong-V1Xi4fY", "(Lkotlin/random/Random;J)J", "nextULong-jmpaW-c", "(Lkotlin/random/Random;JJ)J", "Lkotlin/ranges/ULongRange;", "(Lkotlin/random/Random;Lkotlin/ranges/ULongRange;)J", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class URandomKt {
    public static final int nextUInt(Random nextUInt) {
        Intrinsics.checkParameterIsNotNull(nextUInt, "$this$nextUInt");
        return UInt.m88constructorimpl(nextUInt.nextInt());
    }

    /* renamed from: nextUInt-qCasIEU  reason: not valid java name */
    public static final int m848nextUIntqCasIEU(Random nextUInt, int until) {
        Intrinsics.checkParameterIsNotNull(nextUInt, "$this$nextUInt");
        return m847nextUInta8DCA5k(nextUInt, 0, until);
    }

    /* renamed from: nextUInt-a8DCA5k  reason: not valid java name */
    public static final int m847nextUInta8DCA5k(Random nextUInt, int from, int until) {
        Intrinsics.checkParameterIsNotNull(nextUInt, "$this$nextUInt");
        m842checkUIntRangeBoundsJ1ME1BU(from, until);
        int signedFrom = from ^ IntCompanionObject.MIN_VALUE;
        int signedUntil = until ^ IntCompanionObject.MIN_VALUE;
        int signedResult = Integer.MIN_VALUE ^ nextUInt.nextInt(signedFrom, signedUntil);
        return UInt.m88constructorimpl(signedResult);
    }

    public static final int nextUInt(Random nextUInt, UIntRange range) {
        Intrinsics.checkParameterIsNotNull(nextUInt, "$this$nextUInt");
        Intrinsics.checkParameterIsNotNull(range, "range");
        if (!range.isEmpty()) {
            return UnsignedKt.uintCompare(range.getLast(), -1) < 0 ? m847nextUInta8DCA5k(nextUInt, range.getFirst(), UInt.m88constructorimpl(range.getLast() + 1)) : UnsignedKt.uintCompare(range.getFirst(), 0) > 0 ? UInt.m88constructorimpl(m847nextUInta8DCA5k(nextUInt, UInt.m88constructorimpl(range.getFirst() - 1), range.getLast()) + 1) : nextUInt(nextUInt);
        }
        throw new IllegalArgumentException("Cannot get random in empty range: " + range);
    }

    public static final long nextULong(Random nextULong) {
        Intrinsics.checkParameterIsNotNull(nextULong, "$this$nextULong");
        return ULong.m157constructorimpl(nextULong.nextLong());
    }

    /* renamed from: nextULong-V1Xi4fY  reason: not valid java name */
    public static final long m849nextULongV1Xi4fY(Random nextULong, long until) {
        Intrinsics.checkParameterIsNotNull(nextULong, "$this$nextULong");
        return m850nextULongjmpaWc(nextULong, 0L, until);
    }

    /* renamed from: nextULong-jmpaW-c  reason: not valid java name */
    public static final long m850nextULongjmpaWc(Random nextULong, long from, long until) {
        Intrinsics.checkParameterIsNotNull(nextULong, "$this$nextULong");
        m843checkULongRangeBoundseb3DHEI(from, until);
        long signedFrom = from ^ Long.MIN_VALUE;
        long signedUntil = until ^ Long.MIN_VALUE;
        long signedResult = Long.MIN_VALUE ^ nextULong.nextLong(signedFrom, signedUntil);
        return ULong.m157constructorimpl(signedResult);
    }

    public static final long nextULong(Random nextULong, ULongRange range) {
        Intrinsics.checkParameterIsNotNull(nextULong, "$this$nextULong");
        Intrinsics.checkParameterIsNotNull(range, "range");
        if (range.isEmpty()) {
            throw new IllegalArgumentException("Cannot get random in empty range: " + range);
        } else if (UnsignedKt.ulongCompare(range.getLast(), -1L) < 0) {
            return m850nextULongjmpaWc(nextULong, range.getFirst(), ULong.m157constructorimpl(range.getLast() + ULong.m157constructorimpl(4294967295L & 1)));
        } else {
            if (UnsignedKt.ulongCompare(range.getFirst(), 0L) > 0) {
                long j = 4294967295L & 1;
                return ULong.m157constructorimpl(m850nextULongjmpaWc(nextULong, ULong.m157constructorimpl(range.getFirst() - ULong.m157constructorimpl(j)), range.getLast()) + ULong.m157constructorimpl(j));
            }
            return nextULong(nextULong);
        }
    }

    /* renamed from: nextUBytes-EVgfTAA  reason: not valid java name */
    public static final byte[] m844nextUBytesEVgfTAA(Random nextUBytes, byte[] array) {
        Intrinsics.checkParameterIsNotNull(nextUBytes, "$this$nextUBytes");
        Intrinsics.checkParameterIsNotNull(array, "array");
        nextUBytes.nextBytes(array);
        return array;
    }

    public static final byte[] nextUBytes(Random nextUBytes, int size) {
        Intrinsics.checkParameterIsNotNull(nextUBytes, "$this$nextUBytes");
        return UByteArray.m65constructorimpl(nextUBytes.nextBytes(size));
    }

    /* renamed from: nextUBytes-Wvrt4B4$default  reason: not valid java name */
    public static /* synthetic */ byte[] m846nextUBytesWvrt4B4$default(Random random, byte[] bArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = UByteArray.m71getSizeimpl(bArr);
        }
        return m845nextUBytesWvrt4B4(random, bArr, i, i2);
    }

    /* renamed from: nextUBytes-Wvrt4B4  reason: not valid java name */
    public static final byte[] m845nextUBytesWvrt4B4(Random nextUBytes, byte[] array, int fromIndex, int toIndex) {
        Intrinsics.checkParameterIsNotNull(nextUBytes, "$this$nextUBytes");
        Intrinsics.checkParameterIsNotNull(array, "array");
        nextUBytes.nextBytes(array, fromIndex, toIndex);
        return array;
    }

    /* renamed from: checkUIntRangeBounds-J1ME1BU  reason: not valid java name */
    public static final void m842checkUIntRangeBoundsJ1ME1BU(int from, int until) {
        if (!(UnsignedKt.uintCompare(until, from) > 0)) {
            throw new IllegalArgumentException(RandomKt.boundsErrorMessage(UInt.m82boximpl(from), UInt.m82boximpl(until)).toString());
        }
    }

    /* renamed from: checkULongRangeBounds-eb3DHEI  reason: not valid java name */
    public static final void m843checkULongRangeBoundseb3DHEI(long from, long until) {
        if (!(UnsignedKt.ulongCompare(until, from) > 0)) {
            throw new IllegalArgumentException(RandomKt.boundsErrorMessage(ULong.m151boximpl(from), ULong.m151boximpl(until)).toString());
        }
    }
}