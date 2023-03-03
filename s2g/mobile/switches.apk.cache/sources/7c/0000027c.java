package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.utils.BufferUtils;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ShortBuffer;

/* loaded from: classes.dex */
public class IndexArray implements IndexData {
    final ShortBuffer buffer;
    final ByteBuffer byteBuffer;
    private final boolean empty;

    public IndexArray(int maxIndices) {
        this.empty = maxIndices == 0;
        this.byteBuffer = BufferUtils.newUnsafeByteBuffer((this.empty ? 1 : maxIndices) * 2);
        this.buffer = this.byteBuffer.asShortBuffer();
        this.buffer.flip();
        this.byteBuffer.flip();
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public int getNumIndices() {
        if (this.empty) {
            return 0;
        }
        return this.buffer.limit();
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public int getNumMaxIndices() {
        if (this.empty) {
            return 0;
        }
        return this.buffer.capacity();
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void setIndices(short[] indices, int offset, int count) {
        this.buffer.clear();
        this.buffer.put(indices, offset, count);
        this.buffer.flip();
        this.byteBuffer.position(0);
        this.byteBuffer.limit(count << 1);
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void setIndices(ShortBuffer indices) {
        int pos = indices.position();
        this.buffer.clear();
        this.buffer.limit(indices.remaining());
        this.buffer.put(indices);
        this.buffer.flip();
        indices.position(pos);
        this.byteBuffer.position(0);
        this.byteBuffer.limit(this.buffer.limit() << 1);
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void updateIndices(int targetOffset, short[] indices, int offset, int count) {
        int pos = this.byteBuffer.position();
        this.byteBuffer.position(targetOffset * 2);
        BufferUtils.copy(indices, offset, (Buffer) this.byteBuffer, count);
        this.byteBuffer.position(pos);
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public ShortBuffer getBuffer() {
        return this.buffer;
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void bind() {
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void unbind() {
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData
    public void invalidate() {
    }

    @Override // com.badlogic.gdx.graphics.glutils.IndexData, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        BufferUtils.disposeUnsafeByteBuffer(this.byteBuffer);
    }
}