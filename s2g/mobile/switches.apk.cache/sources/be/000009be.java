package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: StringBuilderJVM.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000T\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\f\n\u0002\u0010\r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000b\n\u0002\u0010\u0005\n\u0002\u0010\u0019\n\u0002\u0010\u0006\n\u0002\u0010\u0007\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\u0010\n\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u001a\u0012\u0010\u0000\u001a\u00060\u0001j\u0002`\u0002*\u00060\u0001j\u0002`\u0002\u001a\u001d\u0010\u0000\u001a\u00060\u0001j\u0002`\u0002*\u00060\u0001j\u0002`\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u001f\u0010\u0000\u001a\u00060\u0001j\u0002`\u0002*\u00060\u0001j\u0002`\u00022\b\u0010\u0003\u001a\u0004\u0018\u00010\u0005H\u0087\b\u001a\u0012\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u0007\u001a\u001f\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\b\u0010\u0003\u001a\u0004\u0018\u00010\bH\u0087\b\u001a\u001f\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\b\u0010\u0003\u001a\u0004\u0018\u00010\tH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\nH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u000bH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\fH\u0087\b\u001a\u001f\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\b\u0010\u0003\u001a\u0004\u0018\u00010\u0005H\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\rH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u000eH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u000fH\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u0010H\u0087\b\u001a\u001d\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0003\u001a\u00020\u0011H\u0087\b\u001a\u001f\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\b\u0010\u0003\u001a\u0004\u0018\u00010\u0012H\u0087\b\u001a%\u0010\u0000\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u00072\u000e\u0010\u0003\u001a\n\u0018\u00010\u0006j\u0004\u0018\u0001`\u0007H\u0087\b\u001a\u0014\u0010\u0013\u001a\u00060\u0006j\u0002`\u0007*\u00060\u0006j\u0002`\u0007H\u0007\u001a!\u0010\u0014\u001a\u00020\u0015*\u00060\u0006j\u0002`\u00072\u0006\u0010\u0016\u001a\u00020\u000f2\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\n¨\u0006\u0017"}, d2 = {"appendln", "Ljava/lang/Appendable;", "Lkotlin/text/Appendable;", "value", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "Ljava/lang/StringBuilder;", "Lkotlin/text/StringBuilder;", "Ljava/lang/StringBuffer;", BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, "clear", "set", BuildConfig.FLAVOR, "index", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/text/StringsKt")
/* loaded from: classes.dex */
class StringsKt__StringBuilderJVMKt extends StringsKt__RegexExtensionsKt {
    private static final void set(StringBuilder set, int index, char value) {
        Intrinsics.checkParameterIsNotNull(set, "$this$set");
        set.setCharAt(index, value);
    }

    public static final StringBuilder clear(StringBuilder clear) {
        Intrinsics.checkParameterIsNotNull(clear, "$this$clear");
        clear.setLength(0);
        return clear;
    }

    public static final Appendable appendln(Appendable appendln) {
        Intrinsics.checkParameterIsNotNull(appendln, "$this$appendln");
        Appendable append = appendln.append(SystemProperties.LINE_SEPARATOR);
        Intrinsics.checkExpressionValueIsNotNull(append, "append(SystemProperties.LINE_SEPARATOR)");
        return append;
    }

    private static final Appendable appendln(Appendable $this$appendln, CharSequence value) {
        Appendable append = $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull(append, "append(value)");
        return StringsKt.appendln(append);
    }

    private static final Appendable appendln(Appendable $this$appendln, char value) {
        Appendable append = $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull(append, "append(value)");
        return StringsKt.appendln(append);
    }

    public static final StringBuilder appendln(StringBuilder appendln) {
        Intrinsics.checkParameterIsNotNull(appendln, "$this$appendln");
        appendln.append(SystemProperties.LINE_SEPARATOR);
        Intrinsics.checkExpressionValueIsNotNull(appendln, "append(SystemProperties.LINE_SEPARATOR)");
        return appendln;
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, StringBuffer value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, CharSequence value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, String value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, Object value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, StringBuilder value) {
        $this$appendln.append((CharSequence) value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, char[] value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, char value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, boolean value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, int value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, short value) {
        $this$appendln.append((int) value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value.toInt())");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, byte value) {
        $this$appendln.append((int) value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value.toInt())");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, long value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, float value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }

    private static final StringBuilder appendln(StringBuilder $this$appendln, double value) {
        $this$appendln.append(value);
        Intrinsics.checkExpressionValueIsNotNull($this$appendln, "append(value)");
        return StringsKt.appendln($this$appendln);
    }
}