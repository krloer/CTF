package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.Matrix3;
import com.badlogic.gdx.math.Matrix4;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.ShortBuffer;

/* loaded from: classes.dex */
public final class BufferUtils {
    static Array<ByteBuffer> unsafeBuffers = new Array<>();
    static int allocatedUnsafe = 0;

    public static native void clear(ByteBuffer byteBuffer, int i);

    private static native void copyJni(Buffer buffer, int i, Buffer buffer2, int i2, int i3);

    private static native void copyJni(byte[] bArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(char[] cArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(double[] dArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(float[] fArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(float[] fArr, Buffer buffer, int i, int i2);

    private static native void copyJni(int[] iArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(long[] jArr, int i, Buffer buffer, int i2, int i3);

    private static native void copyJni(short[] sArr, int i, Buffer buffer, int i2, int i3);

    private static native long find(Buffer buffer, int i, int i2, Buffer buffer2, int i3, int i4);

    private static native long find(Buffer buffer, int i, int i2, Buffer buffer2, int i3, int i4, float f);

    private static native long find(Buffer buffer, int i, int i2, float[] fArr, int i3, int i4);

    private static native long find(Buffer buffer, int i, int i2, float[] fArr, int i3, int i4, float f);

    private static native long find(float[] fArr, int i, int i2, Buffer buffer, int i3, int i4);

    private static native long find(float[] fArr, int i, int i2, Buffer buffer, int i3, int i4, float f);

    private static native long find(float[] fArr, int i, int i2, float[] fArr2, int i3, int i4);

    private static native long find(float[] fArr, int i, int i2, float[] fArr2, int i3, int i4, float f);

    private static native void freeMemory(ByteBuffer byteBuffer);

    private static native long getBufferAddress(Buffer buffer);

    private static native ByteBuffer newDisposableByteBuffer(int i);

    private static native void transformV2M3Jni(Buffer buffer, int i, int i2, float[] fArr, int i3);

    private static native void transformV2M3Jni(float[] fArr, int i, int i2, float[] fArr2, int i3);

    private static native void transformV2M4Jni(Buffer buffer, int i, int i2, float[] fArr, int i3);

    private static native void transformV2M4Jni(float[] fArr, int i, int i2, float[] fArr2, int i3);

    private static native void transformV3M3Jni(Buffer buffer, int i, int i2, float[] fArr, int i3);

    private static native void transformV3M3Jni(float[] fArr, int i, int i2, float[] fArr2, int i3);

    private static native void transformV3M4Jni(Buffer buffer, int i, int i2, float[] fArr, int i3);

    private static native void transformV3M4Jni(float[] fArr, int i, int i2, float[] fArr2, int i3);

    private static native void transformV4M4Jni(Buffer buffer, int i, int i2, float[] fArr, int i3);

    private static native void transformV4M4Jni(float[] fArr, int i, int i2, float[] fArr2, int i3);

    private BufferUtils() {
    }

    public static void copy(float[] src, Buffer dst, int numFloats, int offset) {
        if (dst instanceof ByteBuffer) {
            dst.limit(numFloats << 2);
        } else if (dst instanceof FloatBuffer) {
            dst.limit(numFloats);
        }
        copyJni(src, dst, numFloats, offset);
        dst.position(0);
    }

    public static void copy(byte[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements);
    }

    public static void copy(short[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 1));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 1);
    }

    public static void copy(char[] src, int srcOffset, int numElements, Buffer dst) {
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 1);
    }

    public static void copy(int[] src, int srcOffset, int numElements, Buffer dst) {
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 2);
    }

    public static void copy(long[] src, int srcOffset, int numElements, Buffer dst) {
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 3);
    }

    public static void copy(float[] src, int srcOffset, int numElements, Buffer dst) {
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 2);
    }

    public static void copy(double[] src, int srcOffset, int numElements, Buffer dst) {
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 3);
    }

    public static void copy(char[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 1));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 1);
    }

    public static void copy(int[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 2));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 2);
    }

    public static void copy(long[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 3));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 3);
    }

    public static void copy(float[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 2));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 2);
    }

    public static void copy(double[] src, int srcOffset, Buffer dst, int numElements) {
        dst.limit(dst.position() + bytesToElements(dst, numElements << 3));
        copyJni(src, srcOffset, dst, positionInBytes(dst), numElements << 3);
    }

    public static void copy(Buffer src, Buffer dst, int numElements) {
        int numBytes = elementsToBytes(src, numElements);
        dst.limit(dst.position() + bytesToElements(dst, numBytes));
        copyJni(src, positionInBytes(src), dst, positionInBytes(dst), numBytes);
    }

    public static void transform(Buffer data, int dimensions, int strideInBytes, int count, Matrix4 matrix) {
        transform(data, dimensions, strideInBytes, count, matrix, 0);
    }

    public static void transform(float[] data, int dimensions, int strideInBytes, int count, Matrix4 matrix) {
        transform(data, dimensions, strideInBytes, count, matrix, 0);
    }

    public static void transform(Buffer data, int dimensions, int strideInBytes, int count, Matrix4 matrix, int offset) {
        if (dimensions == 2) {
            transformV2M4Jni(data, strideInBytes, count, matrix.val, positionInBytes(data) + offset);
        } else if (dimensions == 3) {
            transformV3M4Jni(data, strideInBytes, count, matrix.val, positionInBytes(data) + offset);
        } else if (dimensions == 4) {
            transformV4M4Jni(data, strideInBytes, count, matrix.val, positionInBytes(data) + offset);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static void transform(float[] data, int dimensions, int strideInBytes, int count, Matrix4 matrix, int offset) {
        if (dimensions == 2) {
            transformV2M4Jni(data, strideInBytes, count, matrix.val, offset);
        } else if (dimensions == 3) {
            transformV3M4Jni(data, strideInBytes, count, matrix.val, offset);
        } else if (dimensions == 4) {
            transformV4M4Jni(data, strideInBytes, count, matrix.val, offset);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static void transform(Buffer data, int dimensions, int strideInBytes, int count, Matrix3 matrix) {
        transform(data, dimensions, strideInBytes, count, matrix, 0);
    }

    public static void transform(float[] data, int dimensions, int strideInBytes, int count, Matrix3 matrix) {
        transform(data, dimensions, strideInBytes, count, matrix, 0);
    }

    public static void transform(Buffer data, int dimensions, int strideInBytes, int count, Matrix3 matrix, int offset) {
        if (dimensions == 2) {
            transformV2M3Jni(data, strideInBytes, count, matrix.val, positionInBytes(data) + offset);
        } else if (dimensions == 3) {
            transformV3M3Jni(data, strideInBytes, count, matrix.val, positionInBytes(data) + offset);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static void transform(float[] data, int dimensions, int strideInBytes, int count, Matrix3 matrix, int offset) {
        if (dimensions == 2) {
            transformV2M3Jni(data, strideInBytes, count, matrix.val, offset);
        } else if (dimensions == 3) {
            transformV3M3Jni(data, strideInBytes, count, matrix.val, offset);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static long findFloats(Buffer vertex, int strideInBytes, Buffer vertices, int numVertices) {
        return find(vertex, positionInBytes(vertex), strideInBytes, vertices, positionInBytes(vertices), numVertices);
    }

    public static long findFloats(float[] vertex, int strideInBytes, Buffer vertices, int numVertices) {
        return find(vertex, 0, strideInBytes, vertices, positionInBytes(vertices), numVertices);
    }

    public static long findFloats(Buffer vertex, int strideInBytes, float[] vertices, int numVertices) {
        return find(vertex, positionInBytes(vertex), strideInBytes, vertices, 0, numVertices);
    }

    public static long findFloats(float[] vertex, int strideInBytes, float[] vertices, int numVertices) {
        return find(vertex, 0, strideInBytes, vertices, 0, numVertices);
    }

    public static long findFloats(Buffer vertex, int strideInBytes, Buffer vertices, int numVertices, float epsilon) {
        return find(vertex, positionInBytes(vertex), strideInBytes, vertices, positionInBytes(vertices), numVertices, epsilon);
    }

    public static long findFloats(float[] vertex, int strideInBytes, Buffer vertices, int numVertices, float epsilon) {
        return find(vertex, 0, strideInBytes, vertices, positionInBytes(vertices), numVertices, epsilon);
    }

    public static long findFloats(Buffer vertex, int strideInBytes, float[] vertices, int numVertices, float epsilon) {
        return find(vertex, positionInBytes(vertex), strideInBytes, vertices, 0, numVertices, epsilon);
    }

    public static long findFloats(float[] vertex, int strideInBytes, float[] vertices, int numVertices, float epsilon) {
        return find(vertex, 0, strideInBytes, vertices, 0, numVertices, epsilon);
    }

    private static int positionInBytes(Buffer dst) {
        if (dst instanceof ByteBuffer) {
            return dst.position();
        }
        if (dst instanceof ShortBuffer) {
            return dst.position() << 1;
        }
        if (dst instanceof CharBuffer) {
            return dst.position() << 1;
        }
        if (dst instanceof IntBuffer) {
            return dst.position() << 2;
        }
        if (dst instanceof LongBuffer) {
            return dst.position() << 3;
        }
        if (dst instanceof FloatBuffer) {
            return dst.position() << 2;
        }
        if (dst instanceof DoubleBuffer) {
            return dst.position() << 3;
        }
        throw new GdxRuntimeException("Can't copy to a " + dst.getClass().getName() + " instance");
    }

    private static int bytesToElements(Buffer dst, int bytes) {
        if (dst instanceof ByteBuffer) {
            return bytes;
        }
        if (dst instanceof ShortBuffer) {
            return bytes >>> 1;
        }
        if (dst instanceof CharBuffer) {
            return bytes >>> 1;
        }
        if (dst instanceof IntBuffer) {
            return bytes >>> 2;
        }
        if (dst instanceof LongBuffer) {
            return bytes >>> 3;
        }
        if (dst instanceof FloatBuffer) {
            return bytes >>> 2;
        }
        if (dst instanceof DoubleBuffer) {
            return bytes >>> 3;
        }
        throw new GdxRuntimeException("Can't copy to a " + dst.getClass().getName() + " instance");
    }

    private static int elementsToBytes(Buffer dst, int elements) {
        if (dst instanceof ByteBuffer) {
            return elements;
        }
        if (dst instanceof ShortBuffer) {
            return elements << 1;
        }
        if (dst instanceof CharBuffer) {
            return elements << 1;
        }
        if (dst instanceof IntBuffer) {
            return elements << 2;
        }
        if (dst instanceof LongBuffer) {
            return elements << 3;
        }
        if (dst instanceof FloatBuffer) {
            return elements << 2;
        }
        if (dst instanceof DoubleBuffer) {
            return elements << 3;
        }
        throw new GdxRuntimeException("Can't copy to a " + dst.getClass().getName() + " instance");
    }

    public static FloatBuffer newFloatBuffer(int numFloats) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numFloats * 4);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asFloatBuffer();
    }

    public static DoubleBuffer newDoubleBuffer(int numDoubles) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numDoubles * 8);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asDoubleBuffer();
    }

    public static ByteBuffer newByteBuffer(int numBytes) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numBytes);
        buffer.order(ByteOrder.nativeOrder());
        return buffer;
    }

    public static ShortBuffer newShortBuffer(int numShorts) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numShorts * 2);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asShortBuffer();
    }

    public static CharBuffer newCharBuffer(int numChars) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numChars * 2);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asCharBuffer();
    }

    public static IntBuffer newIntBuffer(int numInts) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numInts * 4);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asIntBuffer();
    }

    public static LongBuffer newLongBuffer(int numLongs) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(numLongs * 8);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.asLongBuffer();
    }

    public static void disposeUnsafeByteBuffer(ByteBuffer buffer) {
        int size = buffer.capacity();
        synchronized (unsafeBuffers) {
            if (!unsafeBuffers.removeValue(buffer, true)) {
                throw new IllegalArgumentException("buffer not allocated with newUnsafeByteBuffer or already disposed");
            }
        }
        allocatedUnsafe -= size;
        freeMemory(buffer);
    }

    public static boolean isUnsafeByteBuffer(ByteBuffer buffer) {
        boolean contains;
        synchronized (unsafeBuffers) {
            contains = unsafeBuffers.contains(buffer, true);
        }
        return contains;
    }

    public static ByteBuffer newUnsafeByteBuffer(int numBytes) {
        ByteBuffer buffer = newDisposableByteBuffer(numBytes);
        buffer.order(ByteOrder.nativeOrder());
        allocatedUnsafe += numBytes;
        synchronized (unsafeBuffers) {
            unsafeBuffers.add(buffer);
        }
        return buffer;
    }

    public static long getUnsafeBufferAddress(Buffer buffer) {
        return getBufferAddress(buffer) + buffer.position();
    }

    public static ByteBuffer newUnsafeByteBuffer(ByteBuffer buffer) {
        allocatedUnsafe += buffer.capacity();
        synchronized (unsafeBuffers) {
            unsafeBuffers.add(buffer);
        }
        return buffer;
    }

    public static int getAllocatedBytesUnsafe() {
        return allocatedUnsafe;
    }
}