package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.FloatBuffer;

/* loaded from: classes.dex */
public class InstanceBufferObjectSubData implements InstanceData {
    final VertexAttributes attributes;
    final FloatBuffer buffer;
    int bufferHandle;
    final ByteBuffer byteBuffer;
    boolean isBound;
    final boolean isDirect;
    boolean isDirty;
    final boolean isStatic;
    final int usage;

    public InstanceBufferObjectSubData(boolean isStatic, int numInstances, VertexAttribute... instanceAttributes) {
        this(isStatic, numInstances, new VertexAttributes(instanceAttributes));
    }

    public InstanceBufferObjectSubData(boolean isStatic, int numInstances, VertexAttributes instanceAttributes) {
        this.isDirty = false;
        this.isBound = false;
        this.isStatic = isStatic;
        this.attributes = instanceAttributes;
        this.byteBuffer = BufferUtils.newByteBuffer(this.attributes.vertexSize * numInstances);
        this.isDirect = true;
        this.usage = isStatic ? GL20.GL_STATIC_DRAW : GL20.GL_DYNAMIC_DRAW;
        this.buffer = this.byteBuffer.asFloatBuffer();
        this.bufferHandle = createBufferObject();
        this.buffer.flip();
        this.byteBuffer.flip();
    }

    private int createBufferObject() {
        int result = Gdx.gl20.glGenBuffer();
        Gdx.gl20.glBindBuffer(GL20.GL_ARRAY_BUFFER, result);
        Gdx.gl20.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.capacity(), null, this.usage);
        Gdx.gl20.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        return result;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public VertexAttributes getAttributes() {
        return this.attributes;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public int getNumInstances() {
        return (this.buffer.limit() * 4) / this.attributes.vertexSize;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public int getNumMaxInstances() {
        return this.byteBuffer.capacity() / this.attributes.vertexSize;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public FloatBuffer getBuffer() {
        this.isDirty = true;
        return this.buffer;
    }

    private void bufferChanged() {
        if (this.isBound) {
            Gdx.gl20.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), null, this.usage);
            Gdx.gl20.glBufferSubData(GL20.GL_ARRAY_BUFFER, 0, this.byteBuffer.limit(), this.byteBuffer);
            this.isDirty = false;
        }
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void setInstanceData(float[] data, int offset, int count) {
        this.isDirty = true;
        if (this.isDirect) {
            BufferUtils.copy(data, this.byteBuffer, count, offset);
            this.buffer.position(0);
            this.buffer.limit(count);
        } else {
            this.buffer.clear();
            this.buffer.put(data, offset, count);
            this.buffer.flip();
            this.byteBuffer.position(0);
            this.byteBuffer.limit(this.buffer.limit() << 2);
        }
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void setInstanceData(FloatBuffer data, int count) {
        this.isDirty = true;
        if (this.isDirect) {
            BufferUtils.copy(data, this.byteBuffer, count);
            this.buffer.position(0);
            this.buffer.limit(count);
        } else {
            this.buffer.clear();
            this.buffer.put(data);
            this.buffer.flip();
            this.byteBuffer.position(0);
            this.byteBuffer.limit(this.buffer.limit() << 2);
        }
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void updateInstanceData(int targetOffset, float[] data, int sourceOffset, int count) {
        this.isDirty = true;
        if (this.isDirect) {
            int pos = this.byteBuffer.position();
            this.byteBuffer.position(targetOffset * 4);
            BufferUtils.copy(data, sourceOffset, count, (Buffer) this.byteBuffer);
            this.byteBuffer.position(pos);
            bufferChanged();
            return;
        }
        throw new GdxRuntimeException("Buffer must be allocated direct.");
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void updateInstanceData(int targetOffset, FloatBuffer data, int sourceOffset, int count) {
        this.isDirty = true;
        if (this.isDirect) {
            int pos = this.byteBuffer.position();
            this.byteBuffer.position(targetOffset * 4);
            data.position(sourceOffset * 4);
            BufferUtils.copy(data, this.byteBuffer, count);
            this.byteBuffer.position(pos);
            bufferChanged();
            return;
        }
        throw new GdxRuntimeException("Buffer must be allocated direct.");
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void bind(ShaderProgram shader) {
        bind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void bind(ShaderProgram shader, int[] locations) {
        GL20 gl = Gdx.gl20;
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, this.bufferHandle);
        if (this.isDirty) {
            this.byteBuffer.limit(this.buffer.limit() * 4);
            gl.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), this.byteBuffer, this.usage);
            this.isDirty = false;
        }
        int numAttributes = this.attributes.size();
        if (locations == null) {
            for (int i = 0; i < numAttributes; i++) {
                VertexAttribute attribute = this.attributes.get(i);
                int location = shader.getAttributeLocation(attribute.alias);
                if (location >= 0) {
                    int unitOffset = attribute.unit;
                    shader.enableVertexAttribute(location + unitOffset);
                    shader.setVertexAttribute(location + unitOffset, attribute.numComponents, attribute.type, attribute.normalized, this.attributes.vertexSize, attribute.offset);
                    Gdx.gl30.glVertexAttribDivisor(location + unitOffset, 1);
                }
            }
        } else {
            for (int i2 = 0; i2 < numAttributes; i2++) {
                VertexAttribute attribute2 = this.attributes.get(i2);
                int location2 = locations[i2];
                if (location2 >= 0) {
                    int unitOffset2 = attribute2.unit;
                    shader.enableVertexAttribute(location2 + unitOffset2);
                    shader.setVertexAttribute(location2 + unitOffset2, attribute2.numComponents, attribute2.type, attribute2.normalized, this.attributes.vertexSize, attribute2.offset);
                    Gdx.gl30.glVertexAttribDivisor(location2 + unitOffset2, 1);
                }
            }
        }
        this.isBound = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void unbind(ShaderProgram shader) {
        unbind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void unbind(ShaderProgram shader, int[] locations) {
        GL20 gl = Gdx.gl20;
        int numAttributes = this.attributes.size();
        if (locations == null) {
            for (int i = 0; i < numAttributes; i++) {
                VertexAttribute attribute = this.attributes.get(i);
                int location = shader.getAttributeLocation(attribute.alias);
                if (location >= 0) {
                    int unitOffset = attribute.unit;
                    shader.disableVertexAttribute(location + unitOffset);
                }
            }
        } else {
            for (int i2 = 0; i2 < numAttributes; i2++) {
                VertexAttribute attribute2 = this.attributes.get(i2);
                int location2 = locations[i2];
                if (location2 >= 0) {
                    int unitOffset2 = attribute2.unit;
                    shader.enableVertexAttribute(location2 + unitOffset2);
                }
            }
        }
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        this.isBound = false;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void invalidate() {
        this.bufferHandle = createBufferObject();
        this.isDirty = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        GL20 gl = Gdx.gl20;
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        gl.glDeleteBuffer(this.bufferHandle);
        this.bufferHandle = 0;
    }

    public int getBufferHandle() {
        return this.bufferHandle;
    }
}