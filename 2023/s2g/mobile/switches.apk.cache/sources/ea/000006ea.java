package kotlin;

import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.UIntRange;
import s2g.project.game.BuildConfig;

/* compiled from: UByte.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000n\n\u0002\u0018\u0002\n\u0002\u0010\u000f\n\u0000\n\u0002\u0010\u0005\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\u0010\u0000\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0010\u0006\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0010\n\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u000e\b\u0087@\u0018\u0000 f2\b\u0012\u0004\u0012\u00020\u00000\u0001:\u0001fB\u0014\b\u0001\u0012\u0006\u0010\u0002\u001a\u00020\u0003ø\u0001\u0000¢\u0006\u0004\b\u0004\u0010\u0005J\u001b\u0010\b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\u0087\fø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000bJ\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0000H\u0097\nø\u0001\u0000¢\u0006\u0004\b\u000e\u0010\u000fJ\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u0011\u0010\u0012J\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u0014\u0010\u0015J\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u0017\u0010\u0018J\u0013\u0010\u0019\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u001a\u0010\u0005J\u001b\u0010\u001b\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u001c\u0010\u000fJ\u001b\u0010\u001b\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u001d\u0010\u0012J\u001b\u0010\u001b\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\b\u001e\u0010\u001fJ\u001b\u0010\u001b\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\b \u0010\u0018J\u0013\u0010!\u001a\u00020\"2\b\u0010\t\u001a\u0004\u0018\u00010#HÖ\u0003J\t\u0010$\u001a\u00020\rHÖ\u0001J\u0013\u0010%\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b&\u0010\u0005J\u0013\u0010'\u001a\u00020\u0000H\u0087\bø\u0001\u0000¢\u0006\u0004\b(\u0010\u0005J\u001b\u0010)\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b*\u0010\u000fJ\u001b\u0010)\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b+\u0010\u0012J\u001b\u0010)\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\b,\u0010\u001fJ\u001b\u0010)\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\b-\u0010\u0018J\u001b\u0010.\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\u0087\fø\u0001\u0000¢\u0006\u0004\b/\u0010\u000bJ\u001b\u00100\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b1\u0010\u000fJ\u001b\u00100\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b2\u0010\u0012J\u001b\u00100\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\b3\u0010\u001fJ\u001b\u00100\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\b4\u0010\u0018J\u001b\u00105\u001a\u0002062\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b7\u00108J\u001b\u00109\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b:\u0010\u000fJ\u001b\u00109\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b;\u0010\u0012J\u001b\u00109\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\b<\u0010\u001fJ\u001b\u00109\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\b=\u0010\u0018J\u001b\u0010>\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0000H\u0087\nø\u0001\u0000¢\u0006\u0004\b?\u0010\u000fJ\u001b\u0010>\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0010H\u0087\nø\u0001\u0000¢\u0006\u0004\b@\u0010\u0012J\u001b\u0010>\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\u0013H\u0087\nø\u0001\u0000¢\u0006\u0004\bA\u0010\u001fJ\u001b\u0010>\u001a\u00020\u00102\u0006\u0010\t\u001a\u00020\u0016H\u0087\nø\u0001\u0000¢\u0006\u0004\bB\u0010\u0018J\u0010\u0010C\u001a\u00020\u0003H\u0087\b¢\u0006\u0004\bD\u0010\u0005J\u0010\u0010E\u001a\u00020FH\u0087\b¢\u0006\u0004\bG\u0010HJ\u0010\u0010I\u001a\u00020JH\u0087\b¢\u0006\u0004\bK\u0010LJ\u0010\u0010M\u001a\u00020\rH\u0087\b¢\u0006\u0004\bN\u0010OJ\u0010\u0010P\u001a\u00020QH\u0087\b¢\u0006\u0004\bR\u0010SJ\u0010\u0010T\u001a\u00020UH\u0087\b¢\u0006\u0004\bV\u0010WJ\u000f\u0010X\u001a\u00020YH\u0016¢\u0006\u0004\bZ\u0010[J\u0013\u0010\\\u001a\u00020\u0000H\u0087\bø\u0001\u0000¢\u0006\u0004\b]\u0010\u0005J\u0013\u0010^\u001a\u00020\u0010H\u0087\bø\u0001\u0000¢\u0006\u0004\b_\u0010OJ\u0013\u0010`\u001a\u00020\u0013H\u0087\bø\u0001\u0000¢\u0006\u0004\ba\u0010SJ\u0013\u0010b\u001a\u00020\u0016H\u0087\bø\u0001\u0000¢\u0006\u0004\bc\u0010WJ\u001b\u0010d\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\u0087\fø\u0001\u0000¢\u0006\u0004\be\u0010\u000bR\u0016\u0010\u0002\u001a\u00020\u00038\u0000X\u0081\u0004¢\u0006\b\n\u0000\u0012\u0004\b\u0006\u0010\u0007ø\u0001\u0000\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006g"}, d2 = {"Lkotlin/UByte;", BuildConfig.FLAVOR, "data", BuildConfig.FLAVOR, "constructor-impl", "(B)B", "data$annotations", "()V", "and", "other", "and-7apg3OU", "(BB)B", "compareTo", BuildConfig.FLAVOR, "compareTo-7apg3OU", "(BB)I", "Lkotlin/UInt;", "compareTo-WZ4Q5Ns", "(BI)I", "Lkotlin/ULong;", "compareTo-VKZWuLQ", "(BJ)I", "Lkotlin/UShort;", "compareTo-xj2QHRw", "(BS)I", "dec", "dec-impl", "div", "div-7apg3OU", "div-WZ4Q5Ns", "div-VKZWuLQ", "(BJ)J", "div-xj2QHRw", "equals", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "hashCode", "inc", "inc-impl", "inv", "inv-impl", "minus", "minus-7apg3OU", "minus-WZ4Q5Ns", "minus-VKZWuLQ", "minus-xj2QHRw", "or", "or-7apg3OU", "plus", "plus-7apg3OU", "plus-WZ4Q5Ns", "plus-VKZWuLQ", "plus-xj2QHRw", "rangeTo", "Lkotlin/ranges/UIntRange;", "rangeTo-7apg3OU", "(BB)Lkotlin/ranges/UIntRange;", "rem", "rem-7apg3OU", "rem-WZ4Q5Ns", "rem-VKZWuLQ", "rem-xj2QHRw", "times", "times-7apg3OU", "times-WZ4Q5Ns", "times-VKZWuLQ", "times-xj2QHRw", "toByte", "toByte-impl", "toDouble", BuildConfig.FLAVOR, "toDouble-impl", "(B)D", "toFloat", BuildConfig.FLAVOR, "toFloat-impl", "(B)F", "toInt", "toInt-impl", "(B)I", "toLong", BuildConfig.FLAVOR, "toLong-impl", "(B)J", "toShort", BuildConfig.FLAVOR, "toShort-impl", "(B)S", "toString", BuildConfig.FLAVOR, "toString-impl", "(B)Ljava/lang/String;", "toUByte", "toUByte-impl", "toUInt", "toUInt-impl", "toULong", "toULong-impl", "toUShort", "toUShort-impl", "xor", "xor-7apg3OU", "Companion", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class UByte implements Comparable<UByte> {
    public static final Companion Companion = new Companion(null);
    public static final byte MAX_VALUE = -1;
    public static final byte MIN_VALUE = 0;
    public static final int SIZE_BITS = 8;
    public static final int SIZE_BYTES = 1;
    private final byte data;

    /* renamed from: box-impl  reason: not valid java name */
    public static final /* synthetic */ UByte m15boximpl(byte b) {
        return new UByte(b);
    }

    /* renamed from: compareTo-7apg3OU  reason: not valid java name */
    private int m16compareTo7apg3OU(byte b) {
        return m17compareTo7apg3OU(this.data, b);
    }

    public static /* synthetic */ void data$annotations() {
    }

    /* renamed from: equals-impl  reason: not valid java name */
    public static boolean m27equalsimpl(byte b, Object obj) {
        if (obj instanceof UByte) {
            if (b == ((UByte) obj).m62unboximpl()) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: equals-impl0  reason: not valid java name */
    public static final boolean m28equalsimpl0(byte b, byte b2) {
        throw null;
    }

    /* renamed from: hashCode-impl  reason: not valid java name */
    public static int m29hashCodeimpl(byte b) {
        return b;
    }

    public boolean equals(Object obj) {
        return m27equalsimpl(this.data, obj);
    }

    public int hashCode() {
        return m29hashCodeimpl(this.data);
    }

    public String toString() {
        return m56toStringimpl(this.data);
    }

    /* renamed from: unbox-impl  reason: not valid java name */
    public final /* synthetic */ byte m62unboximpl() {
        return this.data;
    }

    private /* synthetic */ UByte(byte data) {
        this.data = data;
    }

    /* renamed from: constructor-impl  reason: not valid java name */
    public static byte m21constructorimpl(byte data) {
        return data;
    }

    @Override // java.lang.Comparable
    public /* bridge */ /* synthetic */ int compareTo(UByte uByte) {
        return m16compareTo7apg3OU(uByte.m62unboximpl());
    }

    /* compiled from: UByte.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0013\u0010\u0003\u001a\u00020\u0004X\u0086Tø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0005R\u0013\u0010\u0006\u001a\u00020\u0004X\u0086Tø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0005R\u000e\u0010\u0007\u001a\u00020\bX\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\bX\u0086T¢\u0006\u0002\n\u0000\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\n"}, d2 = {"Lkotlin/UByte$Companion;", BuildConfig.FLAVOR, "()V", "MAX_VALUE", "Lkotlin/UByte;", "B", "MIN_VALUE", "SIZE_BITS", BuildConfig.FLAVOR, "SIZE_BYTES", "kotlin-stdlib"}, k = 1, mv = {1, 1, 15})
    /* loaded from: classes.dex */
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker $constructor_marker) {
            this();
        }
    }

    /* renamed from: compareTo-7apg3OU  reason: not valid java name */
    private static int m17compareTo7apg3OU(byte $this, byte other) {
        return Intrinsics.compare($this & MAX_VALUE, other & MAX_VALUE);
    }

    /* renamed from: compareTo-xj2QHRw  reason: not valid java name */
    private static final int m20compareToxj2QHRw(byte $this, short other) {
        return Intrinsics.compare($this & MAX_VALUE, 65535 & other);
    }

    /* renamed from: compareTo-WZ4Q5Ns  reason: not valid java name */
    private static final int m19compareToWZ4Q5Ns(byte $this, int other) {
        return UnsignedKt.uintCompare(UInt.m88constructorimpl($this & MAX_VALUE), other);
    }

    /* renamed from: compareTo-VKZWuLQ  reason: not valid java name */
    private static final int m18compareToVKZWuLQ(byte $this, long other) {
        return UnsignedKt.ulongCompare(ULong.m157constructorimpl($this & 255), other);
    }

    /* renamed from: plus-7apg3OU  reason: not valid java name */
    private static final int m37plus7apg3OU(byte $this, byte other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) + UInt.m88constructorimpl(other & MAX_VALUE));
    }

    /* renamed from: plus-xj2QHRw  reason: not valid java name */
    private static final int m40plusxj2QHRw(byte $this, short other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) + UInt.m88constructorimpl(65535 & other));
    }

    /* renamed from: plus-WZ4Q5Ns  reason: not valid java name */
    private static final int m39plusWZ4Q5Ns(byte $this, int other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) + other);
    }

    /* renamed from: plus-VKZWuLQ  reason: not valid java name */
    private static final long m38plusVKZWuLQ(byte $this, long other) {
        return ULong.m157constructorimpl(ULong.m157constructorimpl($this & 255) + other);
    }

    /* renamed from: minus-7apg3OU  reason: not valid java name */
    private static final int m32minus7apg3OU(byte $this, byte other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) - UInt.m88constructorimpl(other & MAX_VALUE));
    }

    /* renamed from: minus-xj2QHRw  reason: not valid java name */
    private static final int m35minusxj2QHRw(byte $this, short other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) - UInt.m88constructorimpl(65535 & other));
    }

    /* renamed from: minus-WZ4Q5Ns  reason: not valid java name */
    private static final int m34minusWZ4Q5Ns(byte $this, int other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) - other);
    }

    /* renamed from: minus-VKZWuLQ  reason: not valid java name */
    private static final long m33minusVKZWuLQ(byte $this, long other) {
        return ULong.m157constructorimpl(ULong.m157constructorimpl($this & 255) - other);
    }

    /* renamed from: times-7apg3OU  reason: not valid java name */
    private static final int m46times7apg3OU(byte $this, byte other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) * UInt.m88constructorimpl(other & MAX_VALUE));
    }

    /* renamed from: times-xj2QHRw  reason: not valid java name */
    private static final int m49timesxj2QHRw(byte $this, short other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) * UInt.m88constructorimpl(65535 & other));
    }

    /* renamed from: times-WZ4Q5Ns  reason: not valid java name */
    private static final int m48timesWZ4Q5Ns(byte $this, int other) {
        return UInt.m88constructorimpl(UInt.m88constructorimpl($this & MAX_VALUE) * other);
    }

    /* renamed from: times-VKZWuLQ  reason: not valid java name */
    private static final long m47timesVKZWuLQ(byte $this, long other) {
        return ULong.m157constructorimpl(ULong.m157constructorimpl($this & 255) * other);
    }

    /* renamed from: div-7apg3OU  reason: not valid java name */
    private static final int m23div7apg3OU(byte $this, byte other) {
        return UnsignedKt.m286uintDivideJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), UInt.m88constructorimpl(other & MAX_VALUE));
    }

    /* renamed from: div-xj2QHRw  reason: not valid java name */
    private static final int m26divxj2QHRw(byte $this, short other) {
        return UnsignedKt.m286uintDivideJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), UInt.m88constructorimpl(65535 & other));
    }

    /* renamed from: div-WZ4Q5Ns  reason: not valid java name */
    private static final int m25divWZ4Q5Ns(byte $this, int other) {
        return UnsignedKt.m286uintDivideJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), other);
    }

    /* renamed from: div-VKZWuLQ  reason: not valid java name */
    private static final long m24divVKZWuLQ(byte $this, long other) {
        return UnsignedKt.m288ulongDivideeb3DHEI(ULong.m157constructorimpl($this & 255), other);
    }

    /* renamed from: rem-7apg3OU  reason: not valid java name */
    private static final int m42rem7apg3OU(byte $this, byte other) {
        return UnsignedKt.m287uintRemainderJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), UInt.m88constructorimpl(other & MAX_VALUE));
    }

    /* renamed from: rem-xj2QHRw  reason: not valid java name */
    private static final int m45remxj2QHRw(byte $this, short other) {
        return UnsignedKt.m287uintRemainderJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), UInt.m88constructorimpl(65535 & other));
    }

    /* renamed from: rem-WZ4Q5Ns  reason: not valid java name */
    private static final int m44remWZ4Q5Ns(byte $this, int other) {
        return UnsignedKt.m287uintRemainderJ1ME1BU(UInt.m88constructorimpl($this & MAX_VALUE), other);
    }

    /* renamed from: rem-VKZWuLQ  reason: not valid java name */
    private static final long m43remVKZWuLQ(byte $this, long other) {
        return UnsignedKt.m289ulongRemaindereb3DHEI(ULong.m157constructorimpl($this & 255), other);
    }

    /* renamed from: inc-impl  reason: not valid java name */
    private static final byte m30incimpl(byte $this) {
        return m21constructorimpl((byte) ($this + 1));
    }

    /* renamed from: dec-impl  reason: not valid java name */
    private static final byte m22decimpl(byte $this) {
        return m21constructorimpl((byte) ($this - 1));
    }

    /* renamed from: rangeTo-7apg3OU  reason: not valid java name */
    private static final UIntRange m41rangeTo7apg3OU(byte $this, byte other) {
        return new UIntRange(UInt.m88constructorimpl($this & MAX_VALUE), UInt.m88constructorimpl(other & MAX_VALUE), null);
    }

    /* renamed from: and-7apg3OU  reason: not valid java name */
    private static final byte m14and7apg3OU(byte $this, byte other) {
        return m21constructorimpl((byte) ($this & other));
    }

    /* renamed from: or-7apg3OU  reason: not valid java name */
    private static final byte m36or7apg3OU(byte $this, byte other) {
        return m21constructorimpl((byte) ($this | other));
    }

    /* renamed from: xor-7apg3OU  reason: not valid java name */
    private static final byte m61xor7apg3OU(byte $this, byte other) {
        return m21constructorimpl((byte) ($this ^ other));
    }

    /* renamed from: inv-impl  reason: not valid java name */
    private static final byte m31invimpl(byte $this) {
        return m21constructorimpl((byte) ($this ^ (-1)));
    }

    /* renamed from: toByte-impl  reason: not valid java name */
    private static final byte m50toByteimpl(byte $this) {
        return $this;
    }

    /* renamed from: toShort-impl  reason: not valid java name */
    private static final short m55toShortimpl(byte $this) {
        return (short) ($this & 255);
    }

    /* renamed from: toInt-impl  reason: not valid java name */
    private static final int m53toIntimpl(byte $this) {
        return $this & MAX_VALUE;
    }

    /* renamed from: toLong-impl  reason: not valid java name */
    private static final long m54toLongimpl(byte $this) {
        return $this & 255;
    }

    /* renamed from: toUByte-impl  reason: not valid java name */
    private static final byte m57toUByteimpl(byte $this) {
        return $this;
    }

    /* renamed from: toUShort-impl  reason: not valid java name */
    private static final short m60toUShortimpl(byte $this) {
        return UShort.m226constructorimpl((short) ($this & 255));
    }

    /* renamed from: toUInt-impl  reason: not valid java name */
    private static final int m58toUIntimpl(byte $this) {
        return UInt.m88constructorimpl($this & MAX_VALUE);
    }

    /* renamed from: toULong-impl  reason: not valid java name */
    private static final long m59toULongimpl(byte $this) {
        return ULong.m157constructorimpl($this & 255);
    }

    /* renamed from: toFloat-impl  reason: not valid java name */
    private static final float m52toFloatimpl(byte $this) {
        return $this & MAX_VALUE;
    }

    /* renamed from: toDouble-impl  reason: not valid java name */
    private static final double m51toDoubleimpl(byte $this) {
        return $this & MAX_VALUE;
    }

    /* renamed from: toString-impl  reason: not valid java name */
    public static String m56toStringimpl(byte $this) {
        return String.valueOf($this & MAX_VALUE);
    }
}