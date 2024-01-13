package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/* loaded from: classes.dex */
public class ETC1 {
    public static int PKM_HEADER_SIZE = 16;
    public static int ETC1_RGB8_OES = 36196;

    private static native void decodeImage(ByteBuffer byteBuffer, int i, ByteBuffer byteBuffer2, int i2, int i3, int i4, int i5);

    private static native ByteBuffer encodeImage(ByteBuffer byteBuffer, int i, int i2, int i3, int i4);

    private static native ByteBuffer encodeImagePKM(ByteBuffer byteBuffer, int i, int i2, int i3, int i4);

    public static native void formatHeader(ByteBuffer byteBuffer, int i, int i2, int i3);

    public static native int getCompressedDataSize(int i, int i2);

    static native int getHeightPKM(ByteBuffer byteBuffer, int i);

    static native int getWidthPKM(ByteBuffer byteBuffer, int i);

    static native boolean isValidPKM(ByteBuffer byteBuffer, int i);

    /* loaded from: classes.dex */
    public static final class ETC1Data implements Disposable {
        public final ByteBuffer compressedData;
        public final int dataOffset;
        public final int height;
        public final int width;

        public ETC1Data(int width, int height, ByteBuffer compressedData, int dataOffset) {
            this.width = width;
            this.height = height;
            this.compressedData = compressedData;
            this.dataOffset = dataOffset;
            checkNPOT();
        }

        public ETC1Data(FileHandle pkmFile) {
            byte[] buffer = new byte[GL20.GL_TEXTURE_MAG_FILTER];
            DataInputStream in = null;
            try {
                try {
                    in = new DataInputStream(new BufferedInputStream(new GZIPInputStream(pkmFile.read())));
                    int fileSize = in.readInt();
                    this.compressedData = BufferUtils.newUnsafeByteBuffer(fileSize);
                    while (true) {
                        int readBytes = in.read(buffer);
                        if (readBytes != -1) {
                            this.compressedData.put(buffer, 0, readBytes);
                        } else {
                            this.compressedData.position(0);
                            this.compressedData.limit(this.compressedData.capacity());
                            StreamUtils.closeQuietly(in);
                            this.width = ETC1.getWidthPKM(this.compressedData, 0);
                            this.height = ETC1.getHeightPKM(this.compressedData, 0);
                            this.dataOffset = ETC1.PKM_HEADER_SIZE;
                            this.compressedData.position(this.dataOffset);
                            checkNPOT();
                            return;
                        }
                    }
                } catch (Exception e) {
                    throw new GdxRuntimeException("Couldn't load pkm file '" + pkmFile + "'", e);
                }
            } catch (Throwable th) {
                StreamUtils.closeQuietly(in);
                throw th;
            }
        }

        private void checkNPOT() {
            if (!MathUtils.isPowerOfTwo(this.width) || !MathUtils.isPowerOfTwo(this.height)) {
                System.out.println("ETC1Data warning: non-power-of-two ETC1 textures may crash the driver of PowerVR GPUs");
            }
        }

        public boolean hasPKMHeader() {
            return this.dataOffset == 16;
        }

        public void write(FileHandle file) {
            DataOutputStream write = null;
            byte[] buffer = new byte[GL20.GL_TEXTURE_MAG_FILTER];
            int writtenBytes = 0;
            this.compressedData.position(0);
            ByteBuffer byteBuffer = this.compressedData;
            byteBuffer.limit(byteBuffer.capacity());
            try {
                try {
                    write = new DataOutputStream(new GZIPOutputStream(file.write(false)));
                    write.writeInt(this.compressedData.capacity());
                    while (writtenBytes != this.compressedData.capacity()) {
                        int bytesToWrite = Math.min(this.compressedData.remaining(), buffer.length);
                        this.compressedData.get(buffer, 0, bytesToWrite);
                        write.write(buffer, 0, bytesToWrite);
                        writtenBytes += bytesToWrite;
                    }
                    StreamUtils.closeQuietly(write);
                    this.compressedData.position(this.dataOffset);
                    ByteBuffer byteBuffer2 = this.compressedData;
                    byteBuffer2.limit(byteBuffer2.capacity());
                } catch (Exception e) {
                    throw new GdxRuntimeException("Couldn't write PKM file to '" + file + "'", e);
                }
            } catch (Throwable th) {
                StreamUtils.closeQuietly(write);
                throw th;
            }
        }

        @Override // com.badlogic.gdx.utils.Disposable
        public void dispose() {
            BufferUtils.disposeUnsafeByteBuffer(this.compressedData);
        }

        public String toString() {
            if (hasPKMHeader()) {
                StringBuilder sb = new StringBuilder();
                sb.append(ETC1.isValidPKM(this.compressedData, 0) ? "valid" : "invalid");
                sb.append(" pkm [");
                sb.append(ETC1.getWidthPKM(this.compressedData, 0));
                sb.append("x");
                sb.append(ETC1.getHeightPKM(this.compressedData, 0));
                sb.append("], compressed: ");
                sb.append(this.compressedData.capacity() - ETC1.PKM_HEADER_SIZE);
                return sb.toString();
            }
            return "raw [" + this.width + "x" + this.height + "], compressed: " + (this.compressedData.capacity() - ETC1.PKM_HEADER_SIZE);
        }
    }

    private static int getPixelSize(Pixmap.Format format) {
        if (format == Pixmap.Format.RGB565) {
            return 2;
        }
        if (format == Pixmap.Format.RGB888) {
            return 3;
        }
        throw new GdxRuntimeException("Can only handle RGB565 or RGB888 images");
    }

    public static ETC1Data encodeImage(Pixmap pixmap) {
        int pixelSize = getPixelSize(pixmap.getFormat());
        ByteBuffer compressedData = encodeImage(pixmap.getPixels(), 0, pixmap.getWidth(), pixmap.getHeight(), pixelSize);
        BufferUtils.newUnsafeByteBuffer(compressedData);
        return new ETC1Data(pixmap.getWidth(), pixmap.getHeight(), compressedData, 0);
    }

    public static ETC1Data encodeImagePKM(Pixmap pixmap) {
        int pixelSize = getPixelSize(pixmap.getFormat());
        ByteBuffer compressedData = encodeImagePKM(pixmap.getPixels(), 0, pixmap.getWidth(), pixmap.getHeight(), pixelSize);
        BufferUtils.newUnsafeByteBuffer(compressedData);
        return new ETC1Data(pixmap.getWidth(), pixmap.getHeight(), compressedData, 16);
    }

    public static Pixmap decodeImage(ETC1Data etc1Data, Pixmap.Format format) {
        int dataOffset;
        int width;
        int height;
        if (etc1Data.hasPKMHeader()) {
            dataOffset = 16;
            width = getWidthPKM(etc1Data.compressedData, 0);
            height = getHeightPKM(etc1Data.compressedData, 0);
        } else {
            dataOffset = 0;
            width = etc1Data.width;
            height = etc1Data.height;
        }
        int pixelSize = getPixelSize(format);
        Pixmap pixmap = new Pixmap(width, height, format);
        decodeImage(etc1Data.compressedData, dataOffset, pixmap.getPixels(), 0, width, height, pixelSize);
        return pixmap;
    }
}