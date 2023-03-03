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
public class InstanceBufferObject implements InstanceData {
    private VertexAttributes attributes;
    private FloatBuffer buffer;
    private int bufferHandle;
    private ByteBuffer byteBuffer;
    boolean isBound;
    boolean isDirty;
    private boolean ownsBuffer;
    private int usage;

    public InstanceBufferObject(boolean isStatic, int numVertices, VertexAttribute... attributes) {
        this(isStatic, numVertices, new VertexAttributes(attributes));
    }

    public InstanceBufferObject(boolean isStatic, int numVertices, VertexAttributes instanceAttributes) {
        this.isDirty = false;
        this.isBound = false;
        if (Gdx.gl30 == null) {
            throw new GdxRuntimeException("InstanceBufferObject requires a device running with GLES 3.0 compatibilty");
        }
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        ByteBuffer data = BufferUtils.newUnsafeByteBuffer(instanceAttributes.vertexSize * numVertices);
        data.limit(0);
        setBuffer(data, true, instanceAttributes);
        setUsage(isStatic ? GL20.GL_STATIC_DRAW : GL20.GL_DYNAMIC_DRAW);
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

    protected void setBuffer(Buffer data, boolean ownsBuffer, VertexAttributes value) {
        ByteBuffer byteBuffer;
        if (this.isBound) {
            throw new GdxRuntimeException("Cannot change attributes while VBO is bound");
        }
        if (this.ownsBuffer && (byteBuffer = this.byteBuffer) != null) {
            BufferUtils.disposeUnsafeByteBuffer(byteBuffer);
        }
        this.attributes = value;
        if (data instanceof ByteBuffer) {
            this.byteBuffer = (ByteBuffer) data;
            this.ownsBuffer = ownsBuffer;
            int l = this.byteBuffer.limit();
            ByteBuffer byteBuffer2 = this.byteBuffer;
            byteBuffer2.limit(byteBuffer2.capacity());
            this.buffer = this.byteBuffer.asFloatBuffer();
            this.byteBuffer.limit(l);
            this.buffer.limit(l / 4);
            return;
        }
        throw new GdxRuntimeException("Only ByteBuffer is currently supported");
    }

    private void bufferChanged() {
        if (this.isBound) {
            Gdx.gl20.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), null, this.usage);
            Gdx.gl20.glBufferData(GL20.GL_ARRAY_BUFFER, this.byteBuffer.limit(), this.byteBuffer, this.usage);
            this.isDirty = false;
        }
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void setInstanceData(float[] data, int offset, int count) {
        this.isDirty = true;
        BufferUtils.copy(data, this.byteBuffer, count, offset);
        this.buffer.position(0);
        this.buffer.limit(count);
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void setInstanceData(FloatBuffer data, int count) {
        this.isDirty = true;
        BufferUtils.copy(data, this.byteBuffer, count);
        this.buffer.position(0);
        this.buffer.limit(count);
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void updateInstanceData(int targetOffset, float[] data, int sourceOffset, int count) {
        this.isDirty = true;
        int pos = this.byteBuffer.position();
        this.byteBuffer.position(targetOffset * 4);
        BufferUtils.copy(data, sourceOffset, count, (Buffer) this.byteBuffer);
        this.byteBuffer.position(pos);
        this.buffer.position(0);
        bufferChanged();
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void updateInstanceData(int targetOffset, FloatBuffer data, int sourceOffset, int count) {
        this.isDirty = true;
        int pos = this.byteBuffer.position();
        this.byteBuffer.position(targetOffset * 4);
        data.position(sourceOffset * 4);
        BufferUtils.copy(data, this.byteBuffer, count);
        this.byteBuffer.position(pos);
        this.buffer.position(0);
        bufferChanged();
    }

    protected int getUsage() {
        return this.usage;
    }

    protected void setUsage(int value) {
        if (this.isBound) {
            throw new GdxRuntimeException("Cannot change usage while VBO is bound");
        }
        this.usage = value;
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
                    shader.disableVertexAttribute(location2 + unitOffset2);
                }
            }
        }
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        this.isBound = false;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData
    public void invalidate() {
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        this.isDirty = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.InstanceData, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        GL20 gl = Gdx.gl20;
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        gl.glDeleteBuffer(this.bufferHandle);
        this.bufferHandle = 0;
        if (this.ownsBuffer) {
            BufferUtils.disposeUnsafeByteBuffer(this.byteBuffer);
        }
    }
}