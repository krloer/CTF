package kotlin.io;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.NoSuchElementException;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.TypeCastException;
import kotlin.collections.ByteIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import s2g.project.game.BuildConfig;

/* compiled from: IOStreams.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000Z\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\u0012\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0017\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0017\u0010\u0000\u001a\u00020\u0005*\u00020\u00062\b\b\u0002\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0017\u0010\u0007\u001a\u00020\b*\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\nH\u0087\b\u001a\u0017\u0010\u000b\u001a\u00020\f*\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\nH\u0087\b\u001a\u0017\u0010\r\u001a\u00020\u000e*\u00020\u000f2\b\b\u0002\u0010\t\u001a\u00020\nH\u0087\b\u001a\u001c\u0010\u0010\u001a\u00020\u0011*\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00062\b\b\u0002\u0010\u0003\u001a\u00020\u0004\u001a\r\u0010\u0013\u001a\u00020\u000e*\u00020\u0014H\u0087\b\u001a\u001d\u0010\u0013\u001a\u00020\u000e*\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u00042\u0006\u0010\u0016\u001a\u00020\u0004H\u0087\b\u001a\r\u0010\u0017\u001a\u00020\u0018*\u00020\u0001H\u0086\u0002\u001a\f\u0010\u0019\u001a\u00020\u0014*\u00020\u0002H\u0007\u001a\u0016\u0010\u0019\u001a\u00020\u0014*\u00020\u00022\b\b\u0002\u0010\u001a\u001a\u00020\u0004H\u0007\u001a\u0017\u0010\u001b\u001a\u00020\u001c*\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\nH\u0087\b\u001a\u0017\u0010\u001d\u001a\u00020\u001e*\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\nH\u0087\b¨\u0006\u001f"}, d2 = {"buffered", "Ljava/io/BufferedInputStream;", "Ljava/io/InputStream;", "bufferSize", BuildConfig.FLAVOR, "Ljava/io/BufferedOutputStream;", "Ljava/io/OutputStream;", "bufferedReader", "Ljava/io/BufferedReader;", "charset", "Ljava/nio/charset/Charset;", "bufferedWriter", "Ljava/io/BufferedWriter;", "byteInputStream", "Ljava/io/ByteArrayInputStream;", BuildConfig.FLAVOR, "copyTo", BuildConfig.FLAVOR, "out", "inputStream", BuildConfig.FLAVOR, "offset", "length", "iterator", "Lkotlin/collections/ByteIterator;", "readBytes", "estimatedSize", "reader", "Ljava/io/InputStreamReader;", "writer", "Ljava/io/OutputStreamWriter;", "kotlin-stdlib"}, k = 2, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class ByteStreamsKt {
    public static final ByteIterator iterator(final BufferedInputStream iterator) {
        Intrinsics.checkParameterIsNotNull(iterator, "$this$iterator");
        return new ByteIterator() { // from class: kotlin.io.ByteStreamsKt$iterator$1
            private boolean finished;
            private int nextByte = -1;
            private boolean nextPrepared;

            public final int getNextByte() {
                return this.nextByte;
            }

            public final void setNextByte(int i) {
                this.nextByte = i;
            }

            public final boolean getNextPrepared() {
                return this.nextPrepared;
            }

            public final void setNextPrepared(boolean z) {
                this.nextPrepared = z;
            }

            public final boolean getFinished() {
                return this.finished;
            }

            public final void setFinished(boolean z) {
                this.finished = z;
            }

            private final void prepareNext() {
                if (!this.nextPrepared && !this.finished) {
                    this.nextByte = iterator.read();
                    this.nextPrepared = true;
                    this.finished = this.nextByte == -1;
                }
            }

            @Override // java.util.Iterator
            public boolean hasNext() {
                prepareNext();
                return !this.finished;
            }

            @Override // kotlin.collections.ByteIterator
            public byte nextByte() {
                prepareNext();
                if (this.finished) {
                    throw new NoSuchElementException("Input stream is over.");
                }
                byte res = (byte) this.nextByte;
                this.nextPrepared = false;
                return res;
            }
        };
    }

    private static final ByteArrayInputStream byteInputStream(String $this$byteInputStream, Charset charset) {
        if ($this$byteInputStream != null) {
            byte[] bytes = $this$byteInputStream.getBytes(charset);
            Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
            return new ByteArrayInputStream(bytes);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    static /* synthetic */ ByteArrayInputStream byteInputStream$default(String $this$byteInputStream, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        if ($this$byteInputStream != null) {
            byte[] bytes = $this$byteInputStream.getBytes(charset);
            Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
            return new ByteArrayInputStream(bytes);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
    }

    private static final ByteArrayInputStream inputStream(byte[] $this$inputStream) {
        return new ByteArrayInputStream($this$inputStream);
    }

    private static final ByteArrayInputStream inputStream(byte[] $this$inputStream, int offset, int length) {
        return new ByteArrayInputStream($this$inputStream, offset, length);
    }

    static /* synthetic */ BufferedInputStream buffered$default(InputStream $this$buffered, int bufferSize, int i, Object obj) {
        if ((i & 1) != 0) {
            bufferSize = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return $this$buffered instanceof BufferedInputStream ? (BufferedInputStream) $this$buffered : new BufferedInputStream($this$buffered, bufferSize);
    }

    private static final BufferedInputStream buffered(InputStream $this$buffered, int bufferSize) {
        return $this$buffered instanceof BufferedInputStream ? (BufferedInputStream) $this$buffered : new BufferedInputStream($this$buffered, bufferSize);
    }

    private static final InputStreamReader reader(InputStream $this$reader, Charset charset) {
        return new InputStreamReader($this$reader, charset);
    }

    static /* synthetic */ InputStreamReader reader$default(InputStream $this$reader, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        return new InputStreamReader($this$reader, charset);
    }

    private static final BufferedReader bufferedReader(InputStream $this$bufferedReader, Charset charset) {
        InputStreamReader inputStreamReader = new InputStreamReader($this$bufferedReader, charset);
        return inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, ConstantsKt.DEFAULT_BUFFER_SIZE);
    }

    static /* synthetic */ BufferedReader bufferedReader$default(InputStream $this$bufferedReader, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        InputStreamReader inputStreamReader = new InputStreamReader($this$bufferedReader, charset);
        return inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, ConstantsKt.DEFAULT_BUFFER_SIZE);
    }

    static /* synthetic */ BufferedOutputStream buffered$default(OutputStream $this$buffered, int bufferSize, int i, Object obj) {
        if ((i & 1) != 0) {
            bufferSize = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return $this$buffered instanceof BufferedOutputStream ? (BufferedOutputStream) $this$buffered : new BufferedOutputStream($this$buffered, bufferSize);
    }

    private static final BufferedOutputStream buffered(OutputStream $this$buffered, int bufferSize) {
        return $this$buffered instanceof BufferedOutputStream ? (BufferedOutputStream) $this$buffered : new BufferedOutputStream($this$buffered, bufferSize);
    }

    private static final OutputStreamWriter writer(OutputStream $this$writer, Charset charset) {
        return new OutputStreamWriter($this$writer, charset);
    }

    static /* synthetic */ OutputStreamWriter writer$default(OutputStream $this$writer, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        return new OutputStreamWriter($this$writer, charset);
    }

    private static final BufferedWriter bufferedWriter(OutputStream $this$bufferedWriter, Charset charset) {
        OutputStreamWriter outputStreamWriter = new OutputStreamWriter($this$bufferedWriter, charset);
        return outputStreamWriter instanceof BufferedWriter ? (BufferedWriter) outputStreamWriter : new BufferedWriter(outputStreamWriter, ConstantsKt.DEFAULT_BUFFER_SIZE);
    }

    static /* synthetic */ BufferedWriter bufferedWriter$default(OutputStream $this$bufferedWriter, Charset charset, int i, Object obj) {
        if ((i & 1) != 0) {
            charset = Charsets.UTF_8;
        }
        OutputStreamWriter outputStreamWriter = new OutputStreamWriter($this$bufferedWriter, charset);
        return outputStreamWriter instanceof BufferedWriter ? (BufferedWriter) outputStreamWriter : new BufferedWriter(outputStreamWriter, ConstantsKt.DEFAULT_BUFFER_SIZE);
    }

    public static /* synthetic */ long copyTo$default(InputStream inputStream, OutputStream outputStream, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            i = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return copyTo(inputStream, outputStream, i);
    }

    public static final long copyTo(InputStream copyTo, OutputStream out, int bufferSize) {
        Intrinsics.checkParameterIsNotNull(copyTo, "$this$copyTo");
        Intrinsics.checkParameterIsNotNull(out, "out");
        long bytesCopied = 0;
        byte[] buffer = new byte[bufferSize];
        int bytes = copyTo.read(buffer);
        while (bytes >= 0) {
            out.write(buffer, 0, bytes);
            bytesCopied += bytes;
            bytes = copyTo.read(buffer);
        }
        return bytesCopied;
    }

    public static /* synthetic */ byte[] readBytes$default(InputStream inputStream, int i, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = ConstantsKt.DEFAULT_BUFFER_SIZE;
        }
        return readBytes(inputStream, i);
    }

    @Deprecated(message = "Use readBytes() overload without estimatedSize parameter", replaceWith = @ReplaceWith(expression = "readBytes()", imports = {}))
    public static final byte[] readBytes(InputStream readBytes, int estimatedSize) {
        Intrinsics.checkParameterIsNotNull(readBytes, "$this$readBytes");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(Math.max(estimatedSize, readBytes.available()));
        copyTo$default(readBytes, buffer, 0, 2, null);
        byte[] byteArray = buffer.toByteArray();
        Intrinsics.checkExpressionValueIsNotNull(byteArray, "buffer.toByteArray()");
        return byteArray;
    }

    public static final byte[] readBytes(InputStream readBytes) {
        Intrinsics.checkParameterIsNotNull(readBytes, "$this$readBytes");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(Math.max((int) ConstantsKt.DEFAULT_BUFFER_SIZE, readBytes.available()));
        copyTo$default(readBytes, buffer, 0, 2, null);
        byte[] byteArray = buffer.toByteArray();
        Intrinsics.checkExpressionValueIsNotNull(byteArray, "buffer.toByteArray()");
        return byteArray;
    }
}