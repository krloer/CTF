package kotlin.io;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.internal.PlatformImplementationsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;
import kotlin.sequences.SequencesKt;
import kotlin.text.Charsets;
import s2g.project.game.BuildConfig;

/* compiled from: ReadWrite.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000X\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\u001a\u0017\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0017\u0010\u0000\u001a\u00020\u0005*\u00020\u00062\b\b\u0002\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u001c\u0010\u0007\u001a\u00020\b*\u00020\u00022\u0006\u0010\t\u001a\u00020\u00062\b\b\u0002\u0010\u0003\u001a\u00020\u0004\u001a\u001e\u0010\n\u001a\u00020\u000b*\u00020\u00022\u0012\u0010\f\u001a\u000e\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\u000b0\r\u001a\u0010\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u000e0\u0010*\u00020\u0001\u001a\n\u0010\u0011\u001a\u00020\u0012*\u00020\u0013\u001a\u0010\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u000e0\u0015*\u00020\u0002\u001a\n\u0010\u0016\u001a\u00020\u000e*\u00020\u0002\u001a\u0017\u0010\u0016\u001a\u00020\u000e*\u00020\u00132\b\b\u0002\u0010\u0017\u001a\u00020\u0018H\u0087\b\u001a\r\u0010\u0019\u001a\u00020\u001a*\u00020\u000eH\u0087\b\u001a5\u0010\u001b\u001a\u0002H\u001c\"\u0004\b\u0000\u0010\u001c*\u00020\u00022\u0018\u0010\u001d\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u000e0\u0010\u0012\u0004\u0012\u0002H\u001c0\rH\u0086\bø\u0001\u0000¢\u0006\u0002\u0010\u001f\u0082\u0002\b\n\u0006\b\u0011(\u001e0\u0001¨\u0006 "}, d2 = {"buffered", "Ljava/io/BufferedReader;", "Ljava/io/Reader;", "bufferSize", BuildConfig.FLAVOR, "Ljava/io/BufferedWriter;", "Ljava/io/Writer;", "copyTo", BuildConfig.FLAVOR, "out", "forEachLine", BuildConfig.FLAVOR, "action", "Lkotlin/Function1;", BuildConfig.FLAVOR, "lineSequence", "Lkotlin/sequences/Sequence;", "readBytes", BuildConfig.FLAVOR, "Ljava/net/URL;", "readLines", BuildConfig.FLAVOR, "readText", "charset", "Ljava/nio/charset/Charset;", "reader", "Ljava/io/StringReader;", "useLines", "T", "block", "Requires newer compiler version to be inlined correctly.", "(Ljava/io/Reader;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class TextStreamsKt {
    static /* synthetic */ BufferedReader buffered$default(Reader $this$buffered, int bufferSize, int i, Object obj) {
        if ((i & 1) != 0) {
            bufferSize = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return $this$buffered instanceof BufferedReader ? (BufferedReader) $this$buffered : new BufferedReader($this$buffered, bufferSize);
    }

    private static final BufferedReader buffered(Reader $this$buffered, int bufferSize) {
        return $this$buffered instanceof BufferedReader ? (BufferedReader) $this$buffered : new BufferedReader($this$buffered, bufferSize);
    }

    static /* synthetic */ BufferedWriter buffered$default(Writer $this$buffered, int bufferSize, int i, Object obj) {
        if ((i & 1) != 0) {
            bufferSize = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return $this$buffered instanceof BufferedWriter ? (BufferedWriter) $this$buffered : new BufferedWriter($this$buffered, bufferSize);
    }

    private static final BufferedWriter buffered(Writer $this$buffered, int bufferSize) {
        return $this$buffered instanceof BufferedWriter ? (BufferedWriter) $this$buffered : new BufferedWriter($this$buffered, bufferSize);
    }

    public static final void forEachLine(Reader forEachLine, Function1<? super String, Unit> action) {
        Intrinsics.checkParameterIsNotNull(forEachLine, "$this$forEachLine");
        Intrinsics.checkParameterIsNotNull(action, "action");
        BufferedReader bufferedReader = forEachLine instanceof BufferedReader ? (BufferedReader) forEachLine : new BufferedReader(forEachLine, ConstantsKt.DEFAULT_BUFFER_SIZE);
        Throwable th = null;
        try {
            BufferedReader it$iv = bufferedReader;
            Sequence it = lineSequence(it$iv);
            for (Object element$iv : it) {
                action.invoke(element$iv);
            }
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(bufferedReader, th);
        } finally {
        }
    }

    public static final List<String> readLines(Reader readLines) {
        Intrinsics.checkParameterIsNotNull(readLines, "$this$readLines");
        ArrayList result = new ArrayList();
        forEachLine(readLines, new TextStreamsKt$readLines$1(result));
        return result;
    }

    public static final <T> T useLines(Reader useLines, Function1<? super Sequence<String>, ? extends T> block) {
        Intrinsics.checkParameterIsNotNull(useLines, "$this$useLines");
        Intrinsics.checkParameterIsNotNull(block, "block");
        BufferedReader bufferedReader = useLines instanceof BufferedReader ? (BufferedReader) useLines : new BufferedReader(useLines, ConstantsKt.DEFAULT_BUFFER_SIZE);
        Throwable th = null;
        try {
            BufferedReader it = bufferedReader;
            T invoke = block.invoke(lineSequence(it));
            InlineMarker.finallyStart(1);
            if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 1, 0)) {
                CloseableKt.closeFinally(bufferedReader, th);
            } else {
                bufferedReader.close();
            }
            InlineMarker.finallyEnd(1);
            return invoke;
        } catch (Throwable th2) {
            try {
                throw th2;
            } catch (Throwable th3) {
                InlineMarker.finallyStart(1);
                if (PlatformImplementationsKt.apiVersionIsAtLeast(1, 1, 0)) {
                    CloseableKt.closeFinally(bufferedReader, th2);
                } else {
                    try {
                        bufferedReader.close();
                    } catch (Throwable th4) {
                    }
                }
                InlineMarker.finallyEnd(1);
                throw th3;
            }
        }
    }

    private static final StringReader reader(String $this$reader) {
        return new StringReader($this$reader);
    }

    public static final Sequence<String> lineSequence(BufferedReader lineSequence) {
        Intrinsics.checkParameterIsNotNull(lineSequence, "$this$lineSequence");
        return SequencesKt.constrainOnce(new LinesSequence(lineSequence));
    }

    public static final String readText(Reader readText) {
        Intrinsics.checkParameterIsNotNull(readText, "$this$readText");
        StringWriter buffer = new StringWriter();
        copyTo$default(readText, buffer, 0, 2, null);
        String stringWriter = buffer.toString();
        Intrinsics.checkExpressionValueIsNotNull(stringWriter, "buffer.toString()");
        return stringWriter;
    }

    public static /* synthetic */ long copyTo$default(Reader reader, Writer writer, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            i = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return copyTo(reader, writer, i);
    }

    public static final long copyTo(Reader copyTo, Writer out, int bufferSize) {
        Intrinsics.checkParameterIsNotNull(copyTo, "$this$copyTo");
        Intrinsics.checkParameterIsNotNull(out, "out");
        long charsCopied = 0;
        char[] buffer = new char[bufferSize];
        int chars = copyTo.read(buffer);
        while (chars >= 0) {
            out.write(buffer, 0, chars);
            charsCopied += chars;
            chars = copyTo.read(buffer);
        }
        return charsCopied;
    }

    private static final String readText(URL $this$readText, Charset charset) {
        return new String(readBytes($this$readText), charset);
    }

    static /* synthetic */ String readText$default(URL $this$readText, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        return new String(readBytes($this$readText), charset);
    }

    public static final byte[] readBytes(URL readBytes) {
        Intrinsics.checkParameterIsNotNull(readBytes, "$this$readBytes");
        InputStream openStream = readBytes.openStream();
        Throwable th = null;
        try {
            InputStream it = openStream;
            Intrinsics.checkExpressionValueIsNotNull(it, "it");
            byte[] readBytes2 = ByteStreamsKt.readBytes(it);
            CloseableKt.closeFinally(openStream, th);
            return readBytes2;
        } finally {
        }
    }
}