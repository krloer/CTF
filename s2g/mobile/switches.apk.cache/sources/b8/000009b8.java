package kotlin.text;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt;
import kotlin.internal.PlatformImplementationsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.SequencesKt;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Indent.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\b\u000b\u001a!\u0010\u0000\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0002\b\u0004\u001a\u0011\u0010\u0005\u001a\u00020\u0006*\u00020\u0002H\u0002¢\u0006\u0002\b\u0007\u001a\u0014\u0010\b\u001a\u00020\u0002*\u00020\u00022\b\b\u0002\u0010\u0003\u001a\u00020\u0002\u001aJ\u0010\t\u001a\u00020\u0002*\b\u0012\u0004\u0012\u00020\u00020\n2\u0006\u0010\u000b\u001a\u00020\u00062\u0012\u0010\f\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\u00012\u0014\u0010\r\u001a\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001H\u0082\b¢\u0006\u0002\b\u000e\u001a\u0014\u0010\u000f\u001a\u00020\u0002*\u00020\u00022\b\b\u0002\u0010\u0010\u001a\u00020\u0002\u001a\u001e\u0010\u0011\u001a\u00020\u0002*\u00020\u00022\b\b\u0002\u0010\u0010\u001a\u00020\u00022\b\b\u0002\u0010\u0012\u001a\u00020\u0002\u001a\n\u0010\u0013\u001a\u00020\u0002*\u00020\u0002\u001a\u0014\u0010\u0014\u001a\u00020\u0002*\u00020\u00022\b\b\u0002\u0010\u0012\u001a\u00020\u0002¨\u0006\u0015"}, d2 = {"getIndentFunction", "Lkotlin/Function1;", BuildConfig.FLAVOR, "indent", "getIndentFunction$StringsKt__IndentKt", "indentWidth", BuildConfig.FLAVOR, "indentWidth$StringsKt__IndentKt", "prependIndent", "reindent", BuildConfig.FLAVOR, "resultSizeEstimate", "indentAddFunction", "indentCutFunction", "reindent$StringsKt__IndentKt", "replaceIndent", "newIndent", "replaceIndentByMargin", "marginPrefix", "trimIndent", "trimMargin", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/text/StringsKt")
/* loaded from: classes.dex */
public class StringsKt__IndentKt {
    public static /* synthetic */ String trimMargin$default(String str, String str2, int i, Object obj) {
        if ((i & 1) != 0) {
            str2 = "|";
        }
        return StringsKt.trimMargin(str, str2);
    }

    public static final String trimMargin(String trimMargin, String marginPrefix) {
        Intrinsics.checkParameterIsNotNull(trimMargin, "$this$trimMargin");
        Intrinsics.checkParameterIsNotNull(marginPrefix, "marginPrefix");
        return StringsKt.replaceIndentByMargin(trimMargin, BuildConfig.FLAVOR, marginPrefix);
    }

    public static /* synthetic */ String replaceIndentByMargin$default(String str, String str2, String str3, int i, Object obj) {
        if ((i & 1) != 0) {
            str2 = BuildConfig.FLAVOR;
        }
        if ((i & 2) != 0) {
            str3 = "|";
        }
        return StringsKt.replaceIndentByMargin(str, str2, str3);
    }

    public static final String replaceIndentByMargin(String replaceIndentByMargin, String newIndent, String marginPrefix) {
        Appendable joinTo;
        Collection destination$iv$iv$iv;
        String str;
        String invoke;
        Intrinsics.checkParameterIsNotNull(replaceIndentByMargin, "$this$replaceIndentByMargin");
        Intrinsics.checkParameterIsNotNull(newIndent, "newIndent");
        Intrinsics.checkParameterIsNotNull(marginPrefix, "marginPrefix");
        if (!StringsKt.isBlank(marginPrefix)) {
            List lines = StringsKt.lines(replaceIndentByMargin);
            int resultSizeEstimate$iv = replaceIndentByMargin.length() + (newIndent.length() * lines.size());
            Function1 indentAddFunction$iv = getIndentFunction$StringsKt__IndentKt(newIndent);
            int lastIndex$iv = CollectionsKt.getLastIndex(lines);
            List $this$mapIndexedNotNull$iv$iv = lines;
            Collection destination$iv$iv$iv2 = new ArrayList();
            Collection destination$iv$iv$iv3 = destination$iv$iv$iv2;
            int index$iv$iv$iv$iv = 0;
            for (Object item$iv$iv$iv$iv : $this$mapIndexedNotNull$iv$iv) {
                int index$iv$iv$iv$iv2 = index$iv$iv$iv$iv + 1;
                if (index$iv$iv$iv$iv < 0) {
                    CollectionsKt.throwIndexOverflow();
                }
                int index$iv$iv$iv = index$iv$iv$iv$iv;
                String value$iv = (String) item$iv$iv$iv$iv;
                String str2 = null;
                if ((index$iv$iv$iv != 0 && index$iv$iv$iv != lastIndex$iv) || !StringsKt.isBlank(value$iv)) {
                    String $this$indexOfFirst$iv = value$iv;
                    int $i$f$indexOfFirst = 0;
                    int length = $this$indexOfFirst$iv.length();
                    int index$iv = 0;
                    while (true) {
                        int $i$f$indexOfFirst2 = $i$f$indexOfFirst;
                        if (index$iv < length) {
                            char it = $this$indexOfFirst$iv.charAt(index$iv);
                            if (!CharsKt.isWhitespace(it)) {
                                break;
                            }
                            index$iv++;
                            $i$f$indexOfFirst = $i$f$indexOfFirst2;
                        } else {
                            index$iv = -1;
                            break;
                        }
                    }
                    if (index$iv == -1) {
                        destination$iv$iv$iv = destination$iv$iv$iv3;
                        str = null;
                    } else {
                        destination$iv$iv$iv = destination$iv$iv$iv3;
                        if (!StringsKt.startsWith$default(value$iv, marginPrefix, index$iv, false, 4, (Object) null)) {
                            str = null;
                        } else {
                            int length2 = marginPrefix.length() + index$iv;
                            if (value$iv == null) {
                                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                            }
                            str = value$iv.substring(length2);
                            Intrinsics.checkExpressionValueIsNotNull(str, "(this as java.lang.String).substring(startIndex)");
                        }
                    }
                    str2 = (str == null || (invoke = indentAddFunction$iv.invoke(str)) == null) ? value$iv : invoke;
                } else {
                    destination$iv$iv$iv = destination$iv$iv$iv3;
                }
                if (str2 != null) {
                    destination$iv$iv$iv.add(str2);
                }
                destination$iv$iv$iv3 = destination$iv$iv$iv;
                index$iv$iv$iv$iv = index$iv$iv$iv$iv2;
            }
            joinTo = CollectionsKt.joinTo((List) destination$iv$iv$iv3, new StringBuilder(resultSizeEstimate$iv), (r14 & 2) != 0 ? ", " : "\n", (r14 & 4) != 0 ? BuildConfig.FLAVOR : null, (r14 & 8) != 0 ? BuildConfig.FLAVOR : null, (r14 & 16) != 0 ? -1 : 0, (r14 & 32) != 0 ? "..." : null, (r14 & 64) != 0 ? null : null);
            String sb = ((StringBuilder) joinTo).toString();
            Intrinsics.checkExpressionValueIsNotNull(sb, "mapIndexedNotNull { inde…\"\\n\")\n        .toString()");
            return sb;
        }
        throw new IllegalArgumentException("marginPrefix must be non-blank string.".toString());
    }

    public static final String trimIndent(String trimIndent) {
        Intrinsics.checkParameterIsNotNull(trimIndent, "$this$trimIndent");
        return StringsKt.replaceIndent(trimIndent, BuildConfig.FLAVOR);
    }

    public static /* synthetic */ String replaceIndent$default(String str, String str2, int i, Object obj) {
        if ((i & 1) != 0) {
            str2 = BuildConfig.FLAVOR;
        }
        return StringsKt.replaceIndent(str, str2);
    }

    public static final String replaceIndent(String replaceIndent, String newIndent) {
        Appendable joinTo;
        String str;
        Intrinsics.checkParameterIsNotNull(replaceIndent, "$this$replaceIndent");
        Intrinsics.checkParameterIsNotNull(newIndent, "newIndent");
        List lines = StringsKt.lines(replaceIndent);
        List $this$filter$iv = lines;
        Collection destination$iv$iv = new ArrayList();
        for (Object element$iv$iv : $this$filter$iv) {
            String p1 = (String) element$iv$iv;
            if (!StringsKt.isBlank(p1)) {
                destination$iv$iv.add(element$iv$iv);
            }
        }
        Iterable $this$filter$iv2 = (List) destination$iv$iv;
        Iterable $this$map$iv = $this$filter$iv2;
        Collection destination$iv$iv2 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv, 10));
        for (Object item$iv$iv : $this$map$iv) {
            String p12 = (String) item$iv$iv;
            destination$iv$iv2.add(Integer.valueOf(indentWidth$StringsKt__IndentKt(p12)));
        }
        Integer num = (Integer) CollectionsKt.min((Iterable<? extends Comparable>) ((List) destination$iv$iv2));
        int minCommonIndent = num != null ? num.intValue() : 0;
        int resultSizeEstimate$iv = replaceIndent.length() + (newIndent.length() * lines.size());
        Function1 indentAddFunction$iv = getIndentFunction$StringsKt__IndentKt(newIndent);
        int lastIndex$iv = CollectionsKt.getLastIndex(lines);
        List $this$mapIndexedNotNull$iv$iv = lines;
        Collection destination$iv$iv$iv = new ArrayList();
        int index$iv$iv$iv$iv = 0;
        for (Object item$iv$iv$iv$iv : $this$mapIndexedNotNull$iv$iv) {
            int index$iv$iv$iv$iv2 = index$iv$iv$iv$iv + 1;
            if (index$iv$iv$iv$iv < 0) {
                CollectionsKt.throwIndexOverflow();
            }
            String value$iv = (String) item$iv$iv$iv$iv;
            int index$iv = index$iv$iv$iv$iv;
            if ((index$iv == 0 || index$iv == lastIndex$iv) && StringsKt.isBlank(value$iv)) {
                str = null;
            } else {
                String line = StringsKt.drop(value$iv, minCommonIndent);
                if (line == null || (str = indentAddFunction$iv.invoke(line)) == null) {
                    str = value$iv;
                }
            }
            if (str != null) {
                destination$iv$iv$iv.add(str);
            }
            index$iv$iv$iv$iv = index$iv$iv$iv$iv2;
        }
        joinTo = CollectionsKt.joinTo((List) destination$iv$iv$iv, new StringBuilder(resultSizeEstimate$iv), (r14 & 2) != 0 ? ", " : "\n", (r14 & 4) != 0 ? BuildConfig.FLAVOR : null, (r14 & 8) != 0 ? BuildConfig.FLAVOR : null, (r14 & 16) != 0 ? -1 : 0, (r14 & 32) != 0 ? "..." : null, (r14 & 64) != 0 ? null : null);
        String sb = ((StringBuilder) joinTo).toString();
        Intrinsics.checkExpressionValueIsNotNull(sb, "mapIndexedNotNull { inde…\"\\n\")\n        .toString()");
        return sb;
    }

    public static /* synthetic */ String prependIndent$default(String str, String str2, int i, Object obj) {
        if ((i & 1) != 0) {
            str2 = "    ";
        }
        return StringsKt.prependIndent(str, str2);
    }

    public static final String prependIndent(String prependIndent, String indent) {
        Intrinsics.checkParameterIsNotNull(prependIndent, "$this$prependIndent");
        Intrinsics.checkParameterIsNotNull(indent, "indent");
        return SequencesKt.joinToString$default(SequencesKt.map(StringsKt.lineSequence(prependIndent), new StringsKt__IndentKt$prependIndent$1(indent)), "\n", null, null, 0, null, null, 62, null);
    }

    private static final int indentWidth$StringsKt__IndentKt(String $this$indentWidth) {
        String $this$indexOfFirst$iv = $this$indentWidth;
        int length = $this$indexOfFirst$iv.length();
        int index$iv = 0;
        while (true) {
            if (index$iv < length) {
                if (!CharsKt.isWhitespace($this$indexOfFirst$iv.charAt(index$iv))) {
                    break;
                }
                index$iv++;
            } else {
                index$iv = -1;
                break;
            }
        }
        int it = index$iv;
        return it == -1 ? $this$indentWidth.length() : it;
    }

    private static final Function1<String, String> getIndentFunction$StringsKt__IndentKt(String indent) {
        return indent.length() == 0 ? StringsKt__IndentKt$getIndentFunction$1.INSTANCE : new StringsKt__IndentKt$getIndentFunction$2(indent);
    }

    private static final String reindent$StringsKt__IndentKt(List<String> list, int resultSizeEstimate, Function1<? super String, String> function1, Function1<? super String, String> function12) {
        Appendable joinTo;
        int lastIndex;
        boolean z = false;
        int lastIndex2 = CollectionsKt.getLastIndex(list);
        List<String> $this$mapIndexedNotNull$iv = list;
        Collection destination$iv$iv = new ArrayList();
        int index$iv$iv = 0;
        for (Object item$iv$iv$iv : $this$mapIndexedNotNull$iv) {
            int index$iv$iv$iv = index$iv$iv + 1;
            if (index$iv$iv < 0) {
                if (!PlatformImplementationsKt.apiVersionIsAtLeast(1, 3, 0)) {
                    throw new ArithmeticException("Index overflow has happened.");
                }
                CollectionsKt.throwIndexOverflow();
            }
            String value = (String) item$iv$iv$iv;
            int index = index$iv$iv;
            boolean z2 = z;
            if ((index == 0 || index == lastIndex2) && StringsKt.isBlank(value)) {
                lastIndex = lastIndex2;
                value = null;
            } else {
                String invoke = function12.invoke(value);
                if (invoke != null) {
                    lastIndex = lastIndex2;
                    String invoke2 = function1.invoke(invoke);
                    if (invoke2 != null) {
                        value = invoke2;
                    }
                } else {
                    lastIndex = lastIndex2;
                }
            }
            if (value != null) {
                destination$iv$iv.add(value);
            }
            index$iv$iv = index$iv$iv$iv;
            z = z2;
            lastIndex2 = lastIndex;
        }
        joinTo = CollectionsKt.joinTo((List) destination$iv$iv, new StringBuilder(resultSizeEstimate), (r14 & 2) != 0 ? ", " : "\n", (r14 & 4) != 0 ? BuildConfig.FLAVOR : null, (r14 & 8) != 0 ? BuildConfig.FLAVOR : null, (r14 & 16) != 0 ? -1 : 0, (r14 & 32) != 0 ? "..." : null, (r14 & 64) != 0 ? null : null);
        String sb = ((StringBuilder) joinTo).toString();
        Intrinsics.checkExpressionValueIsNotNull(sb, "mapIndexedNotNull { inde…\"\\n\")\n        .toString()");
        return sb;
    }
}