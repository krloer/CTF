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
public class VertexBufferObject implements VertexData {
    private VertexAttributes attributes;
    private FloatBuffer buffer;
    private int bufferHandle;
    private ByteBuffer byteBuffer;
    boolean isBound;
    boolean isDirty;
    private boolean ownsBuffer;
    private int usage;

    public VertexBufferObject(boolean isStatic, int numVertices, VertexAttribute... attributes) {
        this(isStatic, numVertices, new VertexAttributes(attributes));
    }

    public VertexBufferObject(boolean isStatic, int numVertices, VertexAttributes attributes) {
        this.isDirty = false;
        this.isBound = false;
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        ByteBuffer data = BufferUtils.newUnsafeByteBuffer(attributes.vertexSize * numVertices);
        data.limit(0);
        setBuffer(data, true, attributes);
        setUsage(isStatic ? GL20.GL_STATIC_DRAW : GL20.GL_DYNAMIC_DRAW);
    }

    protected VertexBufferObject(int usage, ByteBuffer data, boolean ownsBuffer, VertexAttributes attributes) {
        this.isDirty = false;
        this.isBound = false;
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        setBuffer(data, ownsBuffer, attributes);
        setUsage(usage);
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

    protected int getUsage() {
        return this.usage;
    }

    protected void setUsage(int value) {
        if (this.isBound) {
            throw new GdxRuntimeException("Cannot change usage while VBO is bound");
        }
        this.usage = value;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void bind(ShaderProgram shader) {
        bind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
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
                    shader.enableVertexAttribute(location);
                    shader.setVertexAttribute(location, attribute.numComponents, attribute.type, attribute.normalized, this.attributes.vertexSize, attribute.offset);
                }
            }
        } else {
            for (int i2 = 0; i2 < numAttributes; i2++) {
                VertexAttribute attribute2 = this.attributes.get(i2);
                int location2 = locations[i2];
                if (location2 >= 0) {
                    shader.enableVertexAttribute(location2);
                    shader.setVertexAttribute(location2, attribute2.numComponents, attribute2.type, attribute2.normalized, this.attributes.vertexSize, attribute2.offset);
                }
            }
        }
        this.isBound = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void unbind(ShaderProgram shader) {
        unbind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void unbind(ShaderProgram shader, int[] locations) {
        GL20 gl = Gdx.gl20;
        int numAttributes = this.attributes.size();
        if (locations == null) {
            for (int i = 0; i < numAttributes; i++) {
                shader.disableVertexAttribute(this.attributes.get(i).alias);
            }
        } else {
            for (int i2 = 0; i2 < numAttributes; i2++) {
                int location = locations[i2];
                if (location >= 0) {
                    shader.disableVertexAttribute(location);
                }
            }
        }
        gl.glBindBuffer(GL20.GL_ARRAY_BUFFER, 0);
        this.isBound = false;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void invalidate() {
        this.bufferHandle = Gdx.gl20.glGenBuffer();
        this.isDirty = true;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData, com.badlogic.gdx.utils.Disposable
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