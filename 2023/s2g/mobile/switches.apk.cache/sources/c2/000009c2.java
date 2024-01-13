package kotlin.text;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.collections.AbstractList;
import kotlin.collections.ArraysKt;
import kotlin.collections.IntIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import kotlin.sequences.SequencesKt;
import s2g.project.game.BuildConfig;

/* compiled from: StringsJVM.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000~\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0019\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\r\n\u0002\b\t\n\u0002\u0010\u0011\n\u0002\u0010\u0000\n\u0002\b\b\n\u0002\u0010\f\n\u0002\b\u0011\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0002\b\r\u001a\u0011\u0010\u0007\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\tH\u0087\b\u001a\u0011\u0010\u0007\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u000bH\u0087\b\u001a\u0011\u0010\u0007\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\u0019\u0010\u0007\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0087\b\u001a!\u0010\u0007\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0011H\u0087\b\u001a)\u0010\u0007\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u000e\u001a\u00020\u000fH\u0087\b\u001a\u0011\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u0014H\u0087\b\u001a!\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0011H\u0087\b\u001a!\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0011H\u0087\b\u001a\n\u0010\u0017\u001a\u00020\u0002*\u00020\u0002\u001a\u0014\u0010\u0017\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0018\u001a\u00020\u0019H\u0007\u001a\u0015\u0010\u001a\u001a\u00020\u0011*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0011H\u0087\b\u001a\u0015\u0010\u001c\u001a\u00020\u0011*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u0011H\u0087\b\u001a\u001d\u0010\u001d\u001a\u00020\u0011*\u00020\u00022\u0006\u0010\u001e\u001a\u00020\u00112\u0006\u0010\u001f\u001a\u00020\u0011H\u0087\b\u001a\u001c\u0010 \u001a\u00020\u0011*\u00020\u00022\u0006\u0010!\u001a\u00020\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a\f\u0010$\u001a\u00020\u0002*\u00020\u0014H\u0007\u001a \u0010$\u001a\u00020\u0002*\u00020\u00142\b\b\u0002\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\u001f\u001a\u00020\u0011H\u0007\u001a\u0015\u0010&\u001a\u00020#*\u00020\u00022\u0006\u0010\n\u001a\u00020\tH\u0087\b\u001a\u0015\u0010&\u001a\u00020#*\u00020\u00022\u0006\u0010'\u001a\u00020(H\u0087\b\u001a\n\u0010)\u001a\u00020\u0002*\u00020\u0002\u001a\u0014\u0010)\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0018\u001a\u00020\u0019H\u0007\u001a\f\u0010*\u001a\u00020\u0002*\u00020\rH\u0007\u001a*\u0010*\u001a\u00020\u0002*\u00020\r2\b\b\u0002\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\u001f\u001a\u00020\u00112\b\b\u0002\u0010+\u001a\u00020#H\u0007\u001a\f\u0010,\u001a\u00020\r*\u00020\u0002H\u0007\u001a*\u0010,\u001a\u00020\r*\u00020\u00022\b\b\u0002\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\u001f\u001a\u00020\u00112\b\b\u0002\u0010+\u001a\u00020#H\u0007\u001a\u001c\u0010-\u001a\u00020#*\u00020\u00022\u0006\u0010.\u001a\u00020\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a \u0010/\u001a\u00020#*\u0004\u0018\u00010\u00022\b\u0010!\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a2\u00100\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0018\u001a\u00020\u00192\u0016\u00101\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010302\"\u0004\u0018\u000103H\u0087\b¢\u0006\u0002\u00104\u001a*\u00100\u001a\u00020\u0002*\u00020\u00022\u0016\u00101\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010302\"\u0004\u0018\u000103H\u0087\b¢\u0006\u0002\u00105\u001a:\u00100\u001a\u00020\u0002*\u00020\u00042\u0006\u0010\u0018\u001a\u00020\u00192\u0006\u00100\u001a\u00020\u00022\u0016\u00101\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010302\"\u0004\u0018\u000103H\u0087\b¢\u0006\u0002\u00106\u001a2\u00100\u001a\u00020\u0002*\u00020\u00042\u0006\u00100\u001a\u00020\u00022\u0016\u00101\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010302\"\u0004\u0018\u000103H\u0087\b¢\u0006\u0002\u00107\u001a\r\u00108\u001a\u00020\u0002*\u00020\u0002H\u0087\b\u001a\n\u00109\u001a\u00020#*\u00020(\u001a\u001d\u0010:\u001a\u00020\u0011*\u00020\u00022\u0006\u0010;\u001a\u00020<2\u0006\u0010=\u001a\u00020\u0011H\u0081\b\u001a\u001d\u0010:\u001a\u00020\u0011*\u00020\u00022\u0006\u0010>\u001a\u00020\u00022\u0006\u0010=\u001a\u00020\u0011H\u0081\b\u001a\u001d\u0010?\u001a\u00020\u0011*\u00020\u00022\u0006\u0010;\u001a\u00020<2\u0006\u0010=\u001a\u00020\u0011H\u0081\b\u001a\u001d\u0010?\u001a\u00020\u0011*\u00020\u00022\u0006\u0010>\u001a\u00020\u00022\u0006\u0010=\u001a\u00020\u0011H\u0081\b\u001a\u001d\u0010@\u001a\u00020\u0011*\u00020\u00022\u0006\u0010\u001b\u001a\u00020\u00112\u0006\u0010A\u001a\u00020\u0011H\u0087\b\u001a4\u0010B\u001a\u00020#*\u00020(2\u0006\u0010C\u001a\u00020\u00112\u0006\u0010!\u001a\u00020(2\u0006\u0010D\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00112\b\b\u0002\u0010\"\u001a\u00020#\u001a4\u0010B\u001a\u00020#*\u00020\u00022\u0006\u0010C\u001a\u00020\u00112\u0006\u0010!\u001a\u00020\u00022\u0006\u0010D\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00112\b\b\u0002\u0010\"\u001a\u00020#\u001a\u0012\u0010E\u001a\u00020\u0002*\u00020(2\u0006\u0010F\u001a\u00020\u0011\u001a$\u0010G\u001a\u00020\u0002*\u00020\u00022\u0006\u0010H\u001a\u00020<2\u0006\u0010I\u001a\u00020<2\b\b\u0002\u0010\"\u001a\u00020#\u001a$\u0010G\u001a\u00020\u0002*\u00020\u00022\u0006\u0010J\u001a\u00020\u00022\u0006\u0010K\u001a\u00020\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a$\u0010L\u001a\u00020\u0002*\u00020\u00022\u0006\u0010H\u001a\u00020<2\u0006\u0010I\u001a\u00020<2\b\b\u0002\u0010\"\u001a\u00020#\u001a$\u0010L\u001a\u00020\u0002*\u00020\u00022\u0006\u0010J\u001a\u00020\u00022\u0006\u0010K\u001a\u00020\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a\"\u0010M\u001a\b\u0012\u0004\u0012\u00020\u00020N*\u00020(2\u0006\u0010O\u001a\u00020P2\b\b\u0002\u0010Q\u001a\u00020\u0011\u001a\u001c\u0010R\u001a\u00020#*\u00020\u00022\u0006\u0010S\u001a\u00020\u00022\b\b\u0002\u0010\"\u001a\u00020#\u001a$\u0010R\u001a\u00020#*\u00020\u00022\u0006\u0010S\u001a\u00020\u00022\u0006\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\"\u001a\u00020#\u001a\u0015\u0010T\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u0011H\u0087\b\u001a\u001d\u0010T\u001a\u00020\u0002*\u00020\u00022\u0006\u0010%\u001a\u00020\u00112\u0006\u0010\u001f\u001a\u00020\u0011H\u0087\b\u001a\u0017\u0010U\u001a\u00020\r*\u00020\u00022\b\b\u0002\u0010\u000e\u001a\u00020\u000fH\u0087\b\u001a\r\u0010V\u001a\u00020\u0014*\u00020\u0002H\u0087\b\u001a3\u0010V\u001a\u00020\u0014*\u00020\u00022\u0006\u0010W\u001a\u00020\u00142\b\b\u0002\u0010X\u001a\u00020\u00112\b\b\u0002\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\u001f\u001a\u00020\u0011H\u0087\b\u001a \u0010V\u001a\u00020\u0014*\u00020\u00022\b\b\u0002\u0010%\u001a\u00020\u00112\b\b\u0002\u0010\u001f\u001a\u00020\u0011H\u0007\u001a\r\u0010Y\u001a\u00020\u0002*\u00020\u0002H\u0087\b\u001a\u0015\u0010Y\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0018\u001a\u00020\u0019H\u0087\b\u001a\u0017\u0010Z\u001a\u00020P*\u00020\u00022\b\b\u0002\u0010[\u001a\u00020\u0011H\u0087\b\u001a\r\u0010\\\u001a\u00020\u0002*\u00020\u0002H\u0087\b\u001a\u0015\u0010\\\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0018\u001a\u00020\u0019H\u0087\b\"%\u0010\u0000\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0001j\b\u0012\u0004\u0012\u00020\u0002`\u0003*\u00020\u00048F¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006¨\u0006]"}, d2 = {"CASE_INSENSITIVE_ORDER", "Ljava/util/Comparator;", BuildConfig.FLAVOR, "Lkotlin/Comparator;", "Lkotlin/String$Companion;", "getCASE_INSENSITIVE_ORDER", "(Lkotlin/jvm/internal/StringCompanionObject;)Ljava/util/Comparator;", "String", "stringBuffer", "Ljava/lang/StringBuffer;", "stringBuilder", "Ljava/lang/StringBuilder;", "bytes", BuildConfig.FLAVOR, "charset", "Ljava/nio/charset/Charset;", "offset", BuildConfig.FLAVOR, "length", "chars", BuildConfig.FLAVOR, "codePoints", BuildConfig.FLAVOR, "capitalize", "locale", "Ljava/util/Locale;", "codePointAt", "index", "codePointBefore", "codePointCount", "beginIndex", "endIndex", "compareTo", "other", "ignoreCase", BuildConfig.FLAVOR, "concatToString", "startIndex", "contentEquals", "charSequence", BuildConfig.FLAVOR, "decapitalize", "decodeToString", "throwOnInvalidSequence", "encodeToByteArray", "endsWith", "suffix", "equals", "format", "args", BuildConfig.FLAVOR, BuildConfig.FLAVOR, "(Ljava/lang/String;Ljava/util/Locale;[Ljava/lang/Object;)Ljava/lang/String;", "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;", "(Lkotlin/jvm/internal/StringCompanionObject;Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;", "(Lkotlin/jvm/internal/StringCompanionObject;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;", "intern", "isBlank", "nativeIndexOf", "ch", BuildConfig.FLAVOR, "fromIndex", "str", "nativeLastIndexOf", "offsetByCodePoints", "codePointOffset", "regionMatches", "thisOffset", "otherOffset", "repeat", "n", "replace", "oldChar", "newChar", "oldValue", "newValue", "replaceFirst", "split", BuildConfig.FLAVOR, "regex", "Ljava/util/regex/Pattern;", "limit", "startsWith", "prefix", "substring", "toByteArray", "toCharArray", "destination", "destinationOffset", "toLowerCase", "toPattern", "flags", "toUpperCase", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/text/StringsKt")
/* loaded from: classes.dex */
public class StringsKt__StringsJVMKt extends StringsKt__StringNumberConversionsKt {
    private static final int nativeIndexOf(String $this$nativeIndexOf, char ch, int fromIndex) {
        if ($this$nativeIndexOf != null) {
            return $this$nativeIndexOf.indexOf(ch, fromIndex);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final int nativeIndexOf(String $this$nativeIndexOf, String str, int fromIndex) {
        if ($this$nativeIndexOf != null) {
            return $this$nativeIndexOf.indexOf(str, fromIndex);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final int nativeLastIndexOf(String $this$nativeLastIndexOf, char ch, int fromIndex) {
        if ($this$nativeLastIndexOf != null) {
            return $this$nativeLastIndexOf.lastIndexOf(ch, fromIndex);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final int nativeLastIndexOf(String $this$nativeLastIndexOf, String str, int fromIndex) {
        if ($this$nativeLastIndexOf != null) {
            return $this$nativeLastIndexOf.lastIndexOf(str, fromIndex);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static /* synthetic */ boolean equals$default(String str, String str2, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        return StringsKt.equals(str, str2, z);
    }

    public static final boolean equals(String $this$equals, String other, boolean ignoreCase) {
        if ($this$equals == null) {
            return other == null;
        } else if (!ignoreCase) {
            return $this$equals.equals(other);
        } else {
            return $this$equals.equalsIgnoreCase(other);
        }
    }

    public static /* synthetic */ String replace$default(String str, char c, char c2, boolean z, int i, Object obj) {
        if ((i & 4) != 0) {
            z = false;
        }
        return StringsKt.replace(str, c, c2, z);
    }

    public static final String replace(String replace, char oldChar, char newChar, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(replace, "$this$replace");
        if (!ignoreCase) {
            String replace2 = replace.replace(oldChar, newChar);
            Intrinsics.checkExpressionValueIsNotNull(replace2, "(this as java.lang.Strin…replace(oldChar, newChar)");
            return replace2;
        }
        return SequencesKt.joinToString$default(StringsKt.splitToSequence$default(replace, new char[]{oldChar}, ignoreCase, 0, 4, (Object) null), String.valueOf(newChar), null, null, 0, null, null, 62, null);
    }

    public static /* synthetic */ String replace$default(String str, String str2, String str3, boolean z, int i, Object obj) {
        if ((i & 4) != 0) {
            z = false;
        }
        return StringsKt.replace(str, str2, str3, z);
    }

    public static final String replace(String replace, String oldValue, String newValue, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(replace, "$this$replace");
        Intrinsics.checkParameterIsNotNull(oldValue, "oldValue");
        Intrinsics.checkParameterIsNotNull(newValue, "newValue");
        return SequencesKt.joinToString$default(StringsKt.splitToSequence$default(replace, new String[]{oldValue}, ignoreCase, 0, 4, (Object) null), newValue, null, null, 0, null, null, 62, null);
    }

    public static /* synthetic */ String replaceFirst$default(String str, char c, char c2, boolean z, int i, Object obj) {
        if ((i & 4) != 0) {
            z = false;
        }
        return StringsKt.replaceFirst(str, c, c2, z);
    }

    public static final String replaceFirst(String replaceFirst, char oldChar, char newChar, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(replaceFirst, "$this$replaceFirst");
        int index = StringsKt.indexOf$default(replaceFirst, oldChar, 0, ignoreCase, 2, (Object) null);
        if (index < 0) {
            return replaceFirst;
        }
        return StringsKt.replaceRange((CharSequence) replaceFirst, index, index + 1, (CharSequence) String.valueOf(newChar)).toString();
    }

    public static /* synthetic */ String replaceFirst$default(String str, String str2, String str3, boolean z, int i, Object obj) {
        if ((i & 4) != 0) {
            z = false;
        }
        return StringsKt.replaceFirst(str, str2, str3, z);
    }

    public static final String replaceFirst(String replaceFirst, String oldValue, String newValue, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(replaceFirst, "$this$replaceFirst");
        Intrinsics.checkParameterIsNotNull(oldValue, "oldValue");
        Intrinsics.checkParameterIsNotNull(newValue, "newValue");
        int index = StringsKt.indexOf$default(replaceFirst, oldValue, 0, ignoreCase, 2, (Object) null);
        if (index < 0) {
            return replaceFirst;
        }
        return StringsKt.replaceRange((CharSequence) replaceFirst, index, oldValue.length() + index, (CharSequence) newValue).toString();
    }

    private static final String toUpperCase(String $this$toUpperCase) {
        if ($this$toUpperCase != null) {
            String upperCase = $this$toUpperCase.toUpperCase();
            Intrinsics.checkExpressionValueIsNotNull(upperCase, "(this as java.lang.String).toUpperCase()");
            return upperCase;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final String toLowerCase(String $this$toLowerCase) {
        if ($this$toLowerCase != null) {
            String lowerCase = $this$toLowerCase.toLowerCase();
            Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase()");
            return lowerCase;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static final String concatToString(char[] concatToString) {
        Intrinsics.checkParameterIsNotNull(concatToString, "$this$concatToString");
        return new String(concatToString);
    }

    public static /* synthetic */ String concatToString$default(char[] cArr, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = cArr.length;
        }
        return StringsKt.concatToString(cArr, i, i2);
    }

    public static final String concatToString(char[] concatToString, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(concatToString, "$this$concatToString");
        AbstractList.Companion.checkBoundsIndexes$kotlin_stdlib(startIndex, endIndex, concatToString.length);
        return new String(concatToString, startIndex, endIndex - startIndex);
    }

    public static /* synthetic */ char[] toCharArray$default(String str, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = str.length();
        }
        return StringsKt.toCharArray(str, i, i2);
    }

    public static final char[] toCharArray(String toCharArray, int startIndex, int endIndex) {
        Intrinsics.checkParameterIsNotNull(toCharArray, "$this$toCharArray");
        AbstractList.Companion.checkBoundsIndexes$kotlin_stdlib(startIndex, endIndex, toCharArray.length());
        char[] cArr = new char[endIndex - startIndex];
        toCharArray.getChars(startIndex, endIndex, cArr, 0);
        return cArr;
    }

    public static final String decodeToString(byte[] decodeToString) {
        Intrinsics.checkParameterIsNotNull(decodeToString, "$this$decodeToString");
        return new String(decodeToString, Charsets.UTF_8);
    }

    public static /* synthetic */ String decodeToString$default(byte[] bArr, int i, int i2, boolean z, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = bArr.length;
        }
        if ((i3 & 4) != 0) {
            z = false;
        }
        return StringsKt.decodeToString(bArr, i, i2, z);
    }

    public static final String decodeToString(byte[] decodeToString, int startIndex, int endIndex, boolean throwOnInvalidSequence) {
        Intrinsics.checkParameterIsNotNull(decodeToString, "$this$decodeToString");
        AbstractList.Companion.checkBoundsIndexes$kotlin_stdlib(startIndex, endIndex, decodeToString.length);
        if (!throwOnInvalidSequence) {
            return new String(decodeToString, startIndex, endIndex - startIndex, Charsets.UTF_8);
        }
        CharsetDecoder decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        String charBuffer = decoder.decode(ByteBuffer.wrap(decodeToString, startIndex, endIndex - startIndex)).toString();
        Intrinsics.checkExpressionValueIsNotNull(charBuffer, "decoder.decode(ByteBuffe…- startIndex)).toString()");
        return charBuffer;
    }

    public static final byte[] encodeToByteArray(String encodeToByteArray) {
        Intrinsics.checkParameterIsNotNull(encodeToByteArray, "$this$encodeToByteArray");
        byte[] bytes = encodeToByteArray.getBytes(Charsets.UTF_8);
        Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
        return bytes;
    }

    public static /* synthetic */ byte[] encodeToByteArray$default(String str, int i, int i2, boolean z, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = str.length();
        }
        if ((i3 & 4) != 0) {
            z = false;
        }
        return StringsKt.encodeToByteArray(str, i, i2, z);
    }

    public static final byte[] encodeToByteArray(String encodeToByteArray, int startIndex, int endIndex, boolean throwOnInvalidSequence) {
        Intrinsics.checkParameterIsNotNull(encodeToByteArray, "$this$encodeToByteArray");
        AbstractList.Companion.checkBoundsIndexes$kotlin_stdlib(startIndex, endIndex, encodeToByteArray.length());
        if (!throwOnInvalidSequence) {
            String substring = encodeToByteArray.substring(startIndex, endIndex);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            Charset charset = Charsets.UTF_8;
            if (substring != null) {
                byte[] bytes = substring.getBytes(charset);
                Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
                return bytes;
            }
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        CharsetEncoder encoder = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer byteBuffer = encoder.encode(CharBuffer.wrap(encodeToByteArray, startIndex, endIndex));
        if (byteBuffer.hasArray() && byteBuffer.arrayOffset() == 0) {
            int remaining = byteBuffer.remaining();
            byte[] array = byteBuffer.array();
            if (array == null) {
                Intrinsics.throwNpe();
            }
            if (remaining == array.length) {
                byte[] array2 = byteBuffer.array();
                Intrinsics.checkExpressionValueIsNotNull(array2, "byteBuffer.array()");
                return array2;
            }
        }
        byte[] it = new byte[byteBuffer.remaining()];
        byteBuffer.get(it);
        return it;
    }

    private static final char[] toCharArray(String $this$toCharArray) {
        if ($this$toCharArray != null) {
            char[] charArray = $this$toCharArray.toCharArray();
            Intrinsics.checkExpressionValueIsNotNull(charArray, "(this as java.lang.String).toCharArray()");
            return charArray;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    static /* synthetic */ char[] toCharArray$default(String $this$toCharArray, char[] destination, int destinationOffset, int startIndex, int endIndex, int i, Object obj) {
        if ((i & 2) != 0) {
            destinationOffset = 0;
        }
        if ((i & 4) != 0) {
            startIndex = 0;
        }
        if ((i & 8) != 0) {
            endIndex = $this$toCharArray.length();
        }
        if ($this$toCharArray == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        $this$toCharArray.getChars(startIndex, endIndex, destination, destinationOffset);
        return destination;
    }

    private static final char[] toCharArray(String $this$toCharArray, char[] destination, int destinationOffset, int startIndex, int endIndex) {
        if ($this$toCharArray == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        $this$toCharArray.getChars(startIndex, endIndex, destination, destinationOffset);
        return destination;
    }

    private static final String format(String $this$format, Object... args) {
        String format = String.format($this$format, Arrays.copyOf(args, args.length));
        Intrinsics.checkExpressionValueIsNotNull(format, "java.lang.String.format(this, *args)");
        return format;
    }

    private static final String format(StringCompanionObject $this$format, String format, Object... args) {
        String format2 = String.format(format, Arrays.copyOf(args, args.length));
        Intrinsics.checkExpressionValueIsNotNull(format2, "java.lang.String.format(format, *args)");
        return format2;
    }

    private static final String format(String $this$format, Locale locale, Object... args) {
        String format = String.format(locale, $this$format, Arrays.copyOf(args, args.length));
        Intrinsics.checkExpressionValueIsNotNull(format, "java.lang.String.format(locale, this, *args)");
        return format;
    }

    private static final String format(StringCompanionObject $this$format, Locale locale, String format, Object... args) {
        String format2 = String.format(locale, format, Arrays.copyOf(args, args.length));
        Intrinsics.checkExpressionValueIsNotNull(format2, "java.lang.String.format(locale, format, *args)");
        return format2;
    }

    public static /* synthetic */ List split$default(CharSequence charSequence, Pattern pattern, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            i = 0;
        }
        return StringsKt.split(charSequence, pattern, i);
    }

    public static final List<String> split(CharSequence split, Pattern regex, int limit) {
        Intrinsics.checkParameterIsNotNull(split, "$this$split");
        Intrinsics.checkParameterIsNotNull(regex, "regex");
        if (limit >= 0) {
            String[] split2 = regex.split(split, limit == 0 ? -1 : limit);
            Intrinsics.checkExpressionValueIsNotNull(split2, "regex.split(this, if (limit == 0) -1 else limit)");
            return ArraysKt.asList(split2);
        }
        throw new IllegalArgumentException(("Limit must be non-negative, but was " + limit + '.').toString());
    }

    private static final String substring(String $this$substring, int startIndex) {
        if ($this$substring != null) {
            String substring = $this$substring.substring(startIndex);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
            return substring;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final String substring(String $this$substring, int startIndex, int endIndex) {
        if ($this$substring != null) {
            String substring = $this$substring.substring(startIndex, endIndex);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            return substring;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static /* synthetic */ boolean startsWith$default(String str, String str2, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        return StringsKt.startsWith(str, str2, z);
    }

    public static final boolean startsWith(String startsWith, String prefix, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(startsWith, "$this$startsWith");
        Intrinsics.checkParameterIsNotNull(prefix, "prefix");
        if (!ignoreCase) {
            return startsWith.startsWith(prefix);
        }
        return StringsKt.regionMatches(startsWith, 0, prefix, 0, prefix.length(), ignoreCase);
    }

    public static /* synthetic */ boolean startsWith$default(String str, String str2, int i, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = false;
        }
        return StringsKt.startsWith(str, str2, i, z);
    }

    public static final boolean startsWith(String startsWith, String prefix, int startIndex, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(startsWith, "$this$startsWith");
        Intrinsics.checkParameterIsNotNull(prefix, "prefix");
        if (!ignoreCase) {
            return startsWith.startsWith(prefix, startIndex);
        }
        return StringsKt.regionMatches(startsWith, startIndex, prefix, 0, prefix.length(), ignoreCase);
    }

    public static /* synthetic */ boolean endsWith$default(String str, String str2, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        return StringsKt.endsWith(str, str2, z);
    }

    public static final boolean endsWith(String endsWith, String suffix, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(endsWith, "$this$endsWith");
        Intrinsics.checkParameterIsNotNull(suffix, "suffix");
        if (!ignoreCase) {
            return endsWith.endsWith(suffix);
        }
        return StringsKt.regionMatches(endsWith, endsWith.length() - suffix.length(), suffix, 0, suffix.length(), true);
    }

    private static final String String(byte[] bytes, int offset, int length, Charset charset) {
        return new String(bytes, offset, length, charset);
    }

    private static final String String(byte[] bytes, Charset charset) {
        return new String(bytes, charset);
    }

    private static final String String(byte[] bytes, int offset, int length) {
        return new String(bytes, offset, length, Charsets.UTF_8);
    }

    private static final String String(byte[] bytes) {
        return new String(bytes, Charsets.UTF_8);
    }

    private static final String String(char[] chars) {
        return new String(chars);
    }

    private static final String String(char[] chars, int offset, int length) {
        return new String(chars, offset, length);
    }

    private static final String String(int[] codePoints, int offset, int length) {
        return new String(codePoints, offset, length);
    }

    private static final String String(StringBuffer stringBuffer) {
        return new String(stringBuffer);
    }

    private static final String String(StringBuilder stringBuilder) {
        return new String(stringBuilder);
    }

    private static final int codePointAt(String $this$codePointAt, int index) {
        if ($this$codePointAt != null) {
            return $this$codePointAt.codePointAt(index);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final int codePointBefore(String $this$codePointBefore, int index) {
        if ($this$codePointBefore != null) {
            return $this$codePointBefore.codePointBefore(index);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final int codePointCount(String $this$codePointCount, int beginIndex, int endIndex) {
        if ($this$codePointCount != null) {
            return $this$codePointCount.codePointCount(beginIndex, endIndex);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static /* synthetic */ int compareTo$default(String str, String str2, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        return StringsKt.compareTo(str, str2, z);
    }

    public static final int compareTo(String compareTo, String other, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(compareTo, "$this$compareTo");
        Intrinsics.checkParameterIsNotNull(other, "other");
        if (ignoreCase) {
            return compareTo.compareToIgnoreCase(other);
        }
        return compareTo.compareTo(other);
    }

    private static final boolean contentEquals(String $this$contentEquals, CharSequence charSequence) {
        if ($this$contentEquals != null) {
            return $this$contentEquals.contentEquals(charSequence);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final boolean contentEquals(String $this$contentEquals, StringBuffer stringBuilder) {
        if ($this$contentEquals != null) {
            return $this$contentEquals.contentEquals(stringBuilder);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final String intern(String $this$intern) {
        if ($this$intern != null) {
            String intern = $this$intern.intern();
            Intrinsics.checkExpressionValueIsNotNull(intern, "(this as java.lang.String).intern()");
            return intern;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static final boolean isBlank(CharSequence isBlank) {
        boolean z;
        Intrinsics.checkParameterIsNotNull(isBlank, "$this$isBlank");
        if (isBlank.length() != 0) {
            Iterable $this$all$iv = StringsKt.getIndices(isBlank);
            if (!($this$all$iv instanceof Collection) || !((Collection) $this$all$iv).isEmpty()) {
                Iterator<Integer> it = $this$all$iv.iterator();
                while (true) {
                    if (it.hasNext()) {
                        int element$iv = ((IntIterator) it).nextInt();
                        if (!CharsKt.isWhitespace(isBlank.charAt(element$iv))) {
                            z = false;
                            break;
                        }
                    } else {
                        z = true;
                        break;
                    }
                }
            } else {
                z = true;
            }
            if (!z) {
                return false;
            }
        }
        return true;
    }

    private static final int offsetByCodePoints(String $this$offsetByCodePoints, int index, int codePointOffset) {
        if ($this$offsetByCodePoints != null) {
            return $this$offsetByCodePoints.offsetByCodePoints(index, codePointOffset);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static final boolean regionMatches(CharSequence regionMatches, int thisOffset, CharSequence other, int otherOffset, int length, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(regionMatches, "$this$regionMatches");
        Intrinsics.checkParameterIsNotNull(other, "other");
        if ((regionMatches instanceof String) && (other instanceof String)) {
            return StringsKt.regionMatches((String) regionMatches, thisOffset, (String) other, otherOffset, length, ignoreCase);
        }
        return StringsKt.regionMatchesImpl(regionMatches, thisOffset, other, otherOffset, length, ignoreCase);
    }

    public static final boolean regionMatches(String regionMatches, int thisOffset, String other, int otherOffset, int length, boolean ignoreCase) {
        Intrinsics.checkParameterIsNotNull(regionMatches, "$this$regionMatches");
        Intrinsics.checkParameterIsNotNull(other, "other");
        if (!ignoreCase) {
            return regionMatches.regionMatches(thisOffset, other, otherOffset, length);
        }
        return regionMatches.regionMatches(ignoreCase, thisOffset, other, otherOffset, length);
    }

    private static final String toLowerCase(String $this$toLowerCase, Locale locale) {
        if ($this$toLowerCase != null) {
            String lowerCase = $this$toLowerCase.toLowerCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
            return lowerCase;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final String toUpperCase(String $this$toUpperCase, Locale locale) {
        if ($this$toUpperCase != null) {
            String upperCase = $this$toUpperCase.toUpperCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(upperCase, "(this as java.lang.String).toUpperCase(locale)");
            return upperCase;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final byte[] toByteArray(String $this$toByteArray, Charset charset) {
        if ($this$toByteArray != null) {
            byte[] bytes = $this$toByteArray.getBytes(charset);
            Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
            return bytes;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    static /* synthetic */ byte[] toByteArray$default(String $this$toByteArray, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        if ($this$toByteArray != null) {
            byte[] bytes = $this$toByteArray.getBytes(charset);
            Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
            return bytes;
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    static /* synthetic */ Pattern toPattern$default(String $this$toPattern, int flags, int i, Object obj) {
        if ((i & 1) != 0) {
            flags = 0;
        }
        Pattern compile = Pattern.compile($this$toPattern, flags);
        Intrinsics.checkExpressionValueIsNotNull(compile, "java.util.regex.Pattern.compile(this, flags)");
        return compile;
    }

    private static final Pattern toPattern(String $this$toPattern, int flags) {
        Pattern compile = Pattern.compile($this$toPattern, flags);
        Intrinsics.checkExpressionValueIsNotNull(compile, "java.util.regex.Pattern.compile(this, flags)");
        return compile;
    }

    public static final String capitalize(String capitalize) {
        Intrinsics.checkParameterIsNotNull(capitalize, "$this$capitalize");
        if ((capitalize.length() > 0) && Character.isLowerCase(capitalize.charAt(0))) {
            StringBuilder sb = new StringBuilder();
            String substring = capitalize.substring(0, 1);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            if (substring != null) {
                String upperCase = substring.toUpperCase();
                Intrinsics.checkExpressionValueIsNotNull(upperCase, "(this as java.lang.String).toUpperCase()");
                sb.append(upperCase);
                String substring2 = capitalize.substring(1);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                sb.append(substring2);
                return sb.toString();
            }
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        return capitalize;
    }

    public static final String capitalize(String capitalize, Locale locale) {
        Intrinsics.checkParameterIsNotNull(capitalize, "$this$capitalize");
        Intrinsics.checkParameterIsNotNull(locale, "locale");
        if (capitalize.length() > 0) {
            char firstChar = capitalize.charAt(0);
            if (Character.isLowerCase(firstChar)) {
                StringBuilder $this$buildString = new StringBuilder();
                char titleChar = Character.toTitleCase(firstChar);
                if (titleChar != Character.toUpperCase(firstChar)) {
                    $this$buildString.append(titleChar);
                } else {
                    String substring = capitalize.substring(0, 1);
                    Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    if (substring == null) {
                        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                    }
                    String upperCase = substring.toUpperCase(locale);
                    Intrinsics.checkExpressionValueIsNotNull(upperCase, "(this as java.lang.String).toUpperCase(locale)");
                    $this$buildString.append(upperCase);
                }
                String substring2 = capitalize.substring(1);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                $this$buildString.append(substring2);
                String sb = $this$buildString.toString();
                Intrinsics.checkExpressionValueIsNotNull(sb, "StringBuilder().apply(builderAction).toString()");
                return sb;
            }
        }
        return capitalize;
    }

    public static final String decapitalize(String decapitalize) {
        Intrinsics.checkParameterIsNotNull(decapitalize, "$this$decapitalize");
        if ((decapitalize.length() > 0) && Character.isUpperCase(decapitalize.charAt(0))) {
            StringBuilder sb = new StringBuilder();
            String substring = decapitalize.substring(0, 1);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            if (substring != null) {
                String lowerCase = substring.toLowerCase();
                Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase()");
                sb.append(lowerCase);
                String substring2 = decapitalize.substring(1);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                sb.append(substring2);
                return sb.toString();
            }
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        return decapitalize;
    }

    public static final String decapitalize(String decapitalize, Locale locale) {
        Intrinsics.checkParameterIsNotNull(decapitalize, "$this$decapitalize");
        Intrinsics.checkParameterIsNotNull(locale, "locale");
        if (!(decapitalize.length() > 0) || Character.isLowerCase(decapitalize.charAt(0))) {
            return decapitalize;
        }
        StringBuilder sb = new StringBuilder();
        String substring = decapitalize.substring(0, 1);
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        if (substring != null) {
            String lowerCase = substring.toLowerCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
            sb.append(lowerCase);
            String substring2 = decapitalize.substring(1);
            Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
            sb.append(substring2);
            return sb.toString();
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    public static final String repeat(CharSequence repeat, int n) {
        Intrinsics.checkParameterIsNotNull(repeat, "$this$repeat");
        int i = 1;
        if (!(n >= 0)) {
            throw new IllegalArgumentException(("Count 'n' must be non-negative, but was " + n + '.').toString());
        } else if (n == 0) {
            return BuildConfig.FLAVOR;
        } else {
            if (n == 1) {
                return repeat.toString();
            }
            int length = repeat.length();
            if (length != 0) {
                if (length == 1) {
                    char charAt = repeat.charAt(0);
                    char[] cArr = new char[n];
                    for (int i2 = 0; i2 < n; i2++) {
                        cArr[i2] = charAt;
                    }
                    return new String(cArr);
                }
                StringBuilder sb = new StringBuilder(repeat.length() * n);
                if (1 <= n) {
                    while (true) {
                        sb.append(repeat);
                        if (i == n) {
                            break;
                        }
                        i++;
                    }
                }
                String sb2 = sb.toString();
                Intrinsics.checkExpressionValueIsNotNull(sb2, "sb.toString()");
                return sb2;
            }
            return BuildConfig.FLAVOR;
        }
    }

    public static final Comparator<String> getCASE_INSENSITIVE_ORDER(StringCompanionObject CASE_INSENSITIVE_ORDER) {
        Intrinsics.checkParameterIsNotNull(CASE_INSENSITIVE_ORDER, "$this$CASE_INSENSITIVE_ORDER");
        Comparator<String> comparator = String.CASE_INSENSITIVE_ORDER;
        Intrinsics.checkExpressionValueIsNotNull(comparator, "java.lang.String.CASE_INSENSITIVE_ORDER");
        return comparator;
    }
}