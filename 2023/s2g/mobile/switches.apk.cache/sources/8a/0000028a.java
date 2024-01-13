package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.utils.BufferUtils;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.FloatBuffer;

/* loaded from: classes.dex */
public class VertexArray implements VertexData {
    final VertexAttributes attributes;
    final FloatBuffer buffer;
    final ByteBuffer byteBuffer;
    boolean isBound;

    public VertexArray(int numVertices, VertexAttribute... attributes) {
        this(numVertices, new VertexAttributes(attributes));
    }

    public VertexArray(int numVertices, VertexAttributes attributes) {
        this.isBound = false;
        this.attributes = attributes;
        this.byteBuffer = BufferUtils.newUnsafeByteBuffer(this.attributes.vertexSize * numVertices);
        this.buffer = this.byteBuffer.asFloatBuffer();
        this.buffer.flip();
        this.byteBuffer.flip();
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        BufferUtils.disposeUnsafeByteBuffer(this.byteBuffer);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public FloatBuffer getBuffer() {
        return this.buffer;
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
    public void setVertices(float[] vertices, int offset, int count) {
        BufferUtils.copy(vertices, this.byteBuffer, count, offset);
        this.buffer.position(0);
        this.buffer.limit(count);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void updateVertices(int targetOffset, float[] vertices, int sourceOffset, int count) {
        int pos = this.byteBuffer.position();
        this.byteBuffer.position(targetOffset * 4);
        BufferUtils.copy(vertices, sourceOffset, count, (Buffer) this.byteBuffer);
        this.byteBuffer.position(pos);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void bind(ShaderProgram shader) {
        bind(shader, null);
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void bind(ShaderProgram shader, int[] locations) {
        int numAttributes = this.attributes.size();
        this.byteBuffer.limit(this.buffer.limit() * 4);
        if (locations == null) {
            for (int i = 0; i < numAttributes; i++) {
                VertexAttribute attribute = this.attributes.get(i);
                int location = shader.getAttributeLocation(attribute.alias);
                if (location >= 0) {
                    shader.enableVertexAttribute(location);
                    if (attribute.type == 5126) {
                        this.buffer.position(attribute.offset / 4);
                        shader.setVertexAttribute(location, attribute.numComponents, attribute.type, attribute.normalized, this.attributes.vertexSize, this.buffer);
                    } else {
                        this.byteBuffer.position(attribute.offset);
                        shader.setVertexAttribute(location, attribute.numComponents, attribute.type, attribute.normalized, this.attributes.vertexSize, this.byteBuffer);
                    }
                }
            }
        } else {
            for (int i2 = 0; i2 < numAttributes; i2++) {
                VertexAttribute attribute2 = this.attributes.get(i2);
                int location2 = locations[i2];
                if (location2 >= 0) {
                    shader.enableVertexAttribute(location2);
                    if (attribute2.type == 5126) {
                        this.buffer.position(attribute2.offset / 4);
                        shader.setVertexAttribute(location2, attribute2.numComponents, attribute2.type, attribute2.normalized, this.attributes.vertexSize, this.buffer);
                    } else {
                        this.byteBuffer.position(attribute2.offset);
                        shader.setVertexAttribute(location2, attribute2.numComponents, attribute2.type, attribute2.normalized, this.attributes.vertexSize, this.byteBuffer);
                    }
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
        this.isBound = false;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public VertexAttributes getAttributes() {
        return this.attributes;
    }

    @Override // com.badlogic.gdx.graphics.glutils.VertexData
    public void invalidate() {
    }
}