package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Shape;

/* loaded from: classes.dex */
public class ChainShape extends Shape {
    private static float[] verts = new float[2];
    boolean isLooped = false;

    private native void jniCreateChain(long j, float[] fArr, int i, int i2);

    private native void jniCreateLoop(long j, float[] fArr, int i, int i2);

    private native void jniGetVertex(long j, int i, float[] fArr);

    private native int jniGetVertexCount(long j);

    private native void jniSetNextVertex(long j, float f, float f2);

    private native void jniSetPrevVertex(long j, float f, float f2);

    private native long newChainShape();

    public ChainShape() {
        this.addr = newChainShape();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChainShape(long addr) {
        this.addr = addr;
    }

    @Override // com.badlogic.gdx.physics.box2d.Shape
    public Shape.Type getType() {
        return Shape.Type.Chain;
    }

    public void createLoop(float[] vertices) {
        jniCreateLoop(this.addr, vertices, 0, vertices.length / 2);
        this.isLooped = true;
    }

    public void createLoop(float[] vertices, int offset, int length) {
        jniCreateLoop(this.addr, vertices, offset, length / 2);
        this.isLooped = true;
    }

    public void createLoop(Vector2[] vertices) {
        float[] verts2 = new float[vertices.length * 2];
        int i = 0;
        int j = 0;
        while (i < vertices.length * 2) {
            verts2[i] = vertices[j].x;
            verts2[i + 1] = vertices[j].y;
            i += 2;
            j++;
        }
        jniCreateLoop(this.addr, verts2, 0, verts2.length / 2);
        this.isLooped = true;
    }

    public void createChain(float[] vertices) {
        jniCreateChain(this.addr, vertices, 0, vertices.length / 2);
        this.isLooped = false;
    }

    public void createChain(float[] vertices, int offset, int length) {
        jniCreateChain(this.addr, vertices, offset, length / 2);
        this.isLooped = false;
    }

    public void createChain(Vector2[] vertices) {
        float[] verts2 = new float[vertices.length * 2];
        int i = 0;
        int j = 0;
        while (i < vertices.length * 2) {
            verts2[i] = vertices[j].x;
            verts2[i + 1] = vertices[j].y;
            i += 2;
            j++;
        }
        jniCreateChain(this.addr, verts2, 0, vertices.length);
        this.isLooped = false;
    }

    public void setPrevVertex(Vector2 prevVertex) {
        setPrevVertex(prevVertex.x, prevVertex.y);
    }

    public void setPrevVertex(float prevVertexX, float prevVertexY) {
        jniSetPrevVertex(this.addr, prevVertexX, prevVertexY);
    }

    public void setNextVertex(Vector2 nextVertex) {
        setNextVertex(nextVertex.x, nextVertex.y);
    }

    public void setNextVertex(float nextVertexX, float nextVertexY) {
        jniSetNextVertex(this.addr, nextVertexX, nextVertexY);
    }

    public int getVertexCount() {
        return jniGetVertexCount(this.addr);
    }

    public void getVertex(int index, Vector2 vertex) {
        jniGetVertex(this.addr, index, verts);
        float[] fArr = verts;
        vertex.x = fArr[0];
        vertex.y = fArr[1];
    }

    public boolean isLooped() {
        return this.isLooped;
    }
}