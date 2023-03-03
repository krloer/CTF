package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.GL30;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.IntArray;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;

/* loaded from: classes.dex */
public class VertexBufferObjectWithVAO implements VertexData {
    static final IntBuffer tmpHandle = BufferUtils.newIntBuffer(1);
    final VertexAttributes attributes;
    final FloatBuffer buffer;
    int bufferHandle;
    final ByteBuffer byteBuffer;
    IntArray cachedLocations;
    boolean isBound;
    boolean isDirty;
    final boolean isStatic;
    final boolean ownsBuffer;
    final int usage;
    int vaoHandle;

    public VertexBufferObjectWithVAO(boolean isStatic, int numVertices, VertexAttribute... attributes) {
        this(isStatic, numVertices, new VertexAttributes(attributes));
    }

    public VertexBufferObjectWithVAO(boolean isStatic, int numVertices, VertexAttributes attributes) {
        this.isDirty = false;
        this.isBound = false;
        this.vaoHandle = -1;
        this.cachedLocations = new IntArray();
        this.isStatic = isStatic;
        this.attributes = attributes;
        this.byteBuffer = BufferUtils.newUnsafeByteBuffer(this.attributes.vertexSize * numVertices);
        this.buffer = this.byteBuffer.asFloatBuffer();
        this.ownsBuffer = true;
        this.buffer.flip();
        this.byteBuffer.flip();
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        this.usage = isStatic ? GL20.GL_STATIC_DRAW : GL20.GL_DYNAMIC_DRAW;
        createVAO();
    }

    public VertexBufferObjectWithVAO(boolean isStatic, ByteBuffer unmanagedBuffer, VertexAttributes attributes) {
        this.isDirty = false;
        this.isBound = false;
        this.vaoHandle = -1;
        this.cachedLocations = new IntArray();
        this.isStatic = isStatic;
        this.attributes = attributes;
        this.byteBuffer = unmanagedBuffer;
        this.ownsBuffer = false;
        this.buffer = this.byteBuffer.asFloatBuffer();
        this.buffer.flip();
        this.byteBuffer.flip();
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        this.usage = isStatic ? GL20.GL_STATIC_DRAW : GL20.GL_DYNAMIC_DRAW;
        createVAO();
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public VertexAttributes getAttributes() {
        return this.attributes;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public int getNumVertices() {
        return (this.buffer.limit() * 4) / this.attributes.vertexSize;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public int getNumMaxVertices() {
        return this.byteBuffer.capacity() / this.attributes.vertexSize;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public FloatBuffer getBuffer() {
        this.isDirty = true;
        return this.buffer;
    }

    private void bufferChanged() {
        if (this.isBound) {
            Gdx.gl20.glBindBuffer(GL20.GL_ARRAY_BUFFER, this.bufferHandle);
            Gdx.gl20.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), this.byteBuffer, this.usage);
            this.isDirty = false;
        }
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void setVertices(float[] vertices, int offset, int count) {
        this.isDirty = true;
        BufferUtils.copy(vertices, this.byteBuffer, count, offset);
        this.buffer.position(0);
        this.buffer.limit(count);
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void updateVertices(int targetOffset, float[] vertices, int sourceOffset, int count) {
        this.isDirty = true;
        int pos = this.byteBuffer.position();
        this.byteBuffer.position(targetOffset * 4);
        BufferUtils.copy(vertices, sourceOffset, count, (Buffer) this.byteBuffer);
        this.byteBuffer.position(pos);
        this.buffer.position(0);
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void bind(ShaderProgram shader) {
        bind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void bind(ShaderProgram shader, int[] locations) {
        GL30 gl = Gdx.gl30;
        gl.glBindVertexArray(this.vaoHandle);
        bindAttributes(shader, locations);
        bindData(gl);
        this.isBound = true;
    }

    private void bindAttributes(ShaderProgram shader, int[] locations) {
        boolean stillValid = this.cachedLocations.size != 0;
        int numAttributes = this.attributes.size();
        if (stillValid) {
            if (locations == null) {
                for (int i = 0; stillValid && i < numAttributes; i++) {
                    stillValid = shader.getAttributeLocation(this.attributes.get(i).alias) == this.cachedLocations.get(i);
                }
            } else {
                int i2 = locations.length;
                stillValid = i2 == this.cachedLocations.size;
                for (int i3 = 0; stillValid && i3 < numAttributes; i3++) {
                    stillValid = locations[i3] == this.cachedLocations.get(i3);
                }
            }
        }
        if (!stillValid) {
            Gdx.gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, this.bufferHandle);
            unbindAttributes(shader);
            this.cachedLocations.clear();
            for (int i4 = 0; i4 < numAttributes; i4++) {
                VertexAttribute attribute = this.attributes.get(i4);
                if (locations == null) {
                    this.cachedLocations.add(shader.getAttributeLocation(attribute.alias));
                } else {
                    this.cachedLocations.add(locations[i4]);
                }
                int location = this.cachedLocations.get(i4);
                if (location >= 0) {
                    shader.enableVertexAttribute(location);
                    shader.setVertexAttribute(location, attribute.numComponents, attribute.type, attribute.normalized, this.attributes.vertexSize, attribute.offset);
                }
            }
        }
    }

    private void unbindAttributes(ShaderProgram shaderProgram) {
        if (this.cachedLocations.size == 0) {
            return;
        }
        int numAttributes = this.attributes.size();
        for (int i = 0; i < numAttributes; i++) {
            int location = this.cachedLocations.get(i);
            if (location >= 0) {
                shaderProgram.disableVertexAttribute(location);
            }
        }
    }

    private void bindData(GL20 gl) {
        if (this.isDirty) {
            gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, this.bufferHandle);
            this.byteBuffer.limit(this.buffer.limit() * 4);
            gl.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), this.byteBuffer, this.usage);
            this.isDirty = false;
        }
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void unbind(ShaderProgram shader) {
        unbind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void unbind(ShaderProgram shader, int[] locations) {
        GL30 gl = Gdx.gl30;
        gl.glBindVertexArray(0);
        this.isBound = false;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void invalidate() {
        this.bufferHandle = Gdx.gl30.glGenBuffer();
        createVAO();
        this.isDirty = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        GL30 gl = Gdx.gl30;
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        gl.glDeleteBuffer(this.bufferHandle);
        this.bufferHandle = 0;
        if (this.ownsBuffer) {
            BufferUtils.disposeUnsafeByteBuffer(this.byteBuffer);
        }
        deleteVAO();
    }

    private void createVAO() {
        tmpHandle.clear();
        Gdx.gl30.glGenVertexArrays(1, tmpHandle);
        this.vaoHandle = tmpHandle.get();
    }

    private void deleteVAO() {
        if (this.vaoHandle != -1) {
            tmpHandle.clear();
            tmpHandle.put(this.vaoHandle);
            tmpHandle.flip();
            Gdx.gl30.glDeleteVertexArrays(1, tmpHandle);
            this.vaoHandle = -1;
        }
    }
}