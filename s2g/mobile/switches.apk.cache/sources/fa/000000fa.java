package com.badlogic.gdx.graphics;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.utils.ByteArray;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;
import java.util.zip.CheckedOutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import kotlin.UByte;

/* loaded from: classes.dex */
public class PixmapIO {
    public static void writeCIM(FileHandle file, Pixmap pixmap) {
        CIM.write(file, pixmap);
    }

    public static Pixmap readCIM(FileHandle file) {
        return CIM.read(file);
    }

    public static void writePNG(FileHandle file, Pixmap pixmap, int compression, boolean flipY) {
        try {
            PNG writer = new PNG((int) (pixmap.getWidth() * pixmap.getHeight() * 1.5f));
            writer.setFlipY(flipY);
            writer.setCompression(compression);
            writer.write(file, pixmap);
            writer.dispose();
        } catch (IOException ex) {
            throw new GdxRuntimeException("Error writing PNG: " + file, ex);
        }
    }

    public static void writePNG(FileHandle file, Pixmap pixmap) {
        writePNG(file, pixmap, -1, false);
    }

    /* loaded from: classes.dex */
    private static class CIM {
        private static final int BUFFER_SIZE = 32000;
        private static final byte[] writeBuffer = new byte[BUFFER_SIZE];
        private static final byte[] readBuffer = new byte[BUFFER_SIZE];

        private CIM() {
        }

        public static void write(FileHandle file, Pixmap pixmap) {
            DataOutputStream out = null;
            try {
                try {
                    DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(file.write(false));
                    out = new DataOutputStream(deflaterOutputStream);
                    out.writeInt(pixmap.getWidth());
                    out.writeInt(pixmap.getHeight());
                    out.writeInt(Pixmap.Format.toGdx2DPixmapFormat(pixmap.getFormat()));
                    ByteBuffer pixelBuf = pixmap.getPixels();
                    pixelBuf.position(0);
                    pixelBuf.limit(pixelBuf.capacity());
                    int remainingBytes = pixelBuf.capacity() % BUFFER_SIZE;
                    int iterations = pixelBuf.capacity() / BUFFER_SIZE;
                    synchronized (writeBuffer) {
                        for (int i = 0; i < iterations; i++) {
                            pixelBuf.get(writeBuffer);
                            out.write(writeBuffer);
                        }
                        pixelBuf.get(writeBuffer, 0, remainingBytes);
                        out.write(writeBuffer, 0, remainingBytes);
                    }
                    pixelBuf.position(0);
                    pixelBuf.limit(pixelBuf.capacity());
                } catch (Exception e) {
                    throw new GdxRuntimeException("Couldn't write Pixmap to file '" + file + "'", e);
                }
            } finally {
                StreamUtils.closeQuietly(out);
            }
        }

        public static Pixmap read(FileHandle file) {
            DataInputStream in = null;
            try {
                try {
                    in = new DataInputStream(new InflaterInputStream(new BufferedInputStream(file.read())));
                    int width = in.readInt();
                    int height = in.readInt();
                    Pixmap.Format format = Pixmap.Format.fromGdx2DPixmapFormat(in.readInt());
                    Pixmap pixmap = new Pixmap(width, height, format);
                    ByteBuffer pixelBuf = pixmap.getPixels();
                    pixelBuf.position(0);
                    pixelBuf.limit(pixelBuf.capacity());
                    synchronized (readBuffer) {
                        while (true) {
                            int readBytes = in.read(readBuffer);
                            if (readBytes > 0) {
                                pixelBuf.put(readBuffer, 0, readBytes);
                            }
                        }
                    }
                    pixelBuf.position(0);
                    pixelBuf.limit(pixelBuf.capacity());
                    return pixmap;
                } catch (Exception e) {
                    throw new GdxRuntimeException("Couldn't read Pixmap from file '" + file + "'", e);
                }
            } finally {
                StreamUtils.closeQuietly(in);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class PNG implements Disposable {
        private static final byte COLOR_ARGB = 6;
        private static final byte COMPRESSION_DEFLATE = 0;
        private static final byte FILTER_NONE = 0;
        private static final int IDAT = 1229209940;
        private static final int IEND = 1229278788;
        private static final int IHDR = 1229472850;
        private static final byte INTERLACE_NONE = 0;
        private static final byte PAETH = 4;
        private static final byte[] SIGNATURE = {-119, 80, 78, 71, 13, 10, 26, 10};
        private final ChunkBuffer buffer;
        private ByteArray curLineBytes;
        private final Deflater deflater;
        private boolean flipY;
        private int lastLineLen;
        private ByteArray lineOutBytes;
        private ByteArray prevLineBytes;

        public PNG() {
            this(GL20.GL_COLOR_BUFFER_BIT);
        }

        public PNG(int initialBufferSize) {
            this.flipY = true;
            this.buffer = new ChunkBuffer(initialBufferSize);
            this.deflater = new Deflater();
        }

        public void setFlipY(boolean flipY) {
            this.flipY = flipY;
        }

        public void setCompression(int level) {
            this.deflater.setLevel(level);
        }

        public void write(FileHandle file, Pixmap pixmap) throws IOException {
            OutputStream output = file.write(false);
            try {
                write(output, pixmap);
            } finally {
                StreamUtils.closeQuietly(output);
            }
        }

        public void write(OutputStream output, Pixmap pixmap) throws IOException {
            byte[] lineOut;
            byte[] curLine;
            byte[] prevLine;
            boolean rgba8888;
            DeflaterOutputStream deflaterOutput = new DeflaterOutputStream(this.buffer, this.deflater);
            DataOutputStream dataOutput = new DataOutputStream(output);
            dataOutput.write(SIGNATURE);
            this.buffer.writeInt(IHDR);
            this.buffer.writeInt(pixmap.getWidth());
            this.buffer.writeInt(pixmap.getHeight());
            this.buffer.writeByte(8);
            this.buffer.writeByte(6);
            int i = 0;
            this.buffer.writeByte(0);
            this.buffer.writeByte(0);
            this.buffer.writeByte(0);
            this.buffer.endChunk(dataOutput);
            this.buffer.writeInt(IDAT);
            this.deflater.reset();
            int lineLen = pixmap.getWidth() * 4;
            ByteArray byteArray = this.lineOutBytes;
            if (byteArray == null) {
                ByteArray byteArray2 = new ByteArray(lineLen);
                this.lineOutBytes = byteArray2;
                lineOut = byteArray2.items;
                ByteArray byteArray3 = new ByteArray(lineLen);
                this.curLineBytes = byteArray3;
                curLine = byteArray3.items;
                ByteArray byteArray4 = new ByteArray(lineLen);
                this.prevLineBytes = byteArray4;
                prevLine = byteArray4.items;
            } else {
                lineOut = byteArray.ensureCapacity(lineLen);
                curLine = this.curLineBytes.ensureCapacity(lineLen);
                prevLine = this.prevLineBytes.ensureCapacity(lineLen);
                int n = this.lastLineLen;
                for (int i2 = 0; i2 < n; i2++) {
                    prevLine[i2] = 0;
                }
            }
            this.lastLineLen = lineLen;
            ByteBuffer pixels = pixmap.getPixels();
            int oldPosition = pixels.position();
            int i3 = 1;
            boolean rgba88882 = pixmap.getFormat() == Pixmap.Format.RGBA8888;
            int y = 0;
            int h = pixmap.getHeight();
            while (y < h) {
                int py = this.flipY ? (h - y) - i3 : y;
                if (rgba88882) {
                    pixels.position(py * lineLen);
                    pixels.get(curLine, i, lineLen);
                    rgba8888 = rgba88882;
                } else {
                    int px = 0;
                    int x = 0;
                    while (px < pixmap.getWidth()) {
                        int pixel = pixmap.getPixel(px, py);
                        int x2 = x + 1;
                        curLine[x] = (byte) ((pixel >> 24) & 255);
                        int x3 = x2 + 1;
                        int py2 = py;
                        curLine[x2] = (byte) ((pixel >> 16) & 255);
                        int x4 = x3 + 1;
                        curLine[x3] = (byte) ((pixel >> 8) & 255);
                        x = x4 + 1;
                        curLine[x4] = (byte) (pixel & 255);
                        px++;
                        rgba88882 = rgba88882;
                        py = py2;
                    }
                    rgba8888 = rgba88882;
                }
                lineOut[0] = (byte) (curLine[0] - prevLine[0]);
                lineOut[1] = (byte) (curLine[1] - prevLine[1]);
                lineOut[2] = (byte) (curLine[2] - prevLine[2]);
                lineOut[3] = (byte) (curLine[3] - prevLine[3]);
                int x5 = 4;
                while (x5 < lineLen) {
                    int a = curLine[x5 - 4] & UByte.MAX_VALUE;
                    int b = prevLine[x5] & UByte.MAX_VALUE;
                    int c = prevLine[x5 - 4] & UByte.MAX_VALUE;
                    int p = (a + b) - c;
                    int pa = p - a;
                    if (pa < 0) {
                        pa = -pa;
                    }
                    int h2 = h;
                    int pb = p - b;
                    if (pb < 0) {
                        pb = -pb;
                    }
                    DataOutputStream dataOutput2 = dataOutput;
                    int pc = p - c;
                    if (pc < 0) {
                        pc = -pc;
                    }
                    if (pa <= pb && pa <= pc) {
                        c = a;
                    } else if (pb <= pc) {
                        c = b;
                    }
                    lineOut[x5] = (byte) (curLine[x5] - c);
                    x5++;
                    h = h2;
                    dataOutput = dataOutput2;
                }
                deflaterOutput.write(4);
                deflaterOutput.write(lineOut, 0, lineLen);
                byte[] temp = curLine;
                curLine = prevLine;
                prevLine = temp;
                y++;
                rgba88882 = rgba8888;
                dataOutput = dataOutput;
                i = 0;
                i3 = 1;
            }
            DataOutputStream dataOutput3 = dataOutput;
            pixels.position(oldPosition);
            deflaterOutput.finish();
            this.buffer.endChunk(dataOutput3);
            this.buffer.writeInt(IEND);
            this.buffer.endChunk(dataOutput3);
            output.flush();
        }

        @Override // com.badlogic.gdx.utils.Disposable
        public void dispose() {
            this.deflater.end();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: classes.dex */
        public static class ChunkBuffer extends DataOutputStream {
            final ByteArrayOutputStream buffer;
            final CRC32 crc;

            ChunkBuffer(int initialSize) {
                this(new ByteArrayOutputStream(initialSize), new CRC32());
            }

            private ChunkBuffer(ByteArrayOutputStream buffer, CRC32 crc) {
                super(new CheckedOutputStream(buffer, crc));
                this.buffer = buffer;
                this.crc = crc;
            }

            public void endChunk(DataOutputStream target) throws IOException {
                flush();
                target.writeInt(this.buffer.size() - 4);
                this.buffer.writeTo(target);
                target.writeInt((int) this.crc.getValue());
                this.buffer.reset();
                this.crc.reset();
            }
        }
    }
}