package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Shape;

/* loaded from: classes.dex */
public class PolygonShape extends Shape {
    private static float[] verts = new float[2];

    private native void jniGetVertex(long j, int i, float[] fArr);

    private native int jniGetVertexCount(long j);

    private native void jniSet(long j, float[] fArr, int i, int i2);

    private native void jniSetAsBox(long j, float f, float f2);

    private native void jniSetAsBox(long j, float f, float f2, float f3, float f4, float f5);

    private native long newPolygonShape();

    public PolygonShape() {
        this.addr = newPolygonShape();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public PolygonShape(long addr) {
        this.addr = addr;
    }

    @Override // com.badlogic.gdx.physics.box2d.Shape
    public Shape.Type getType() {
        return Shape.Type.Polygon;
    }

    public void set(Vector2[] vertices) {
        float[] verts2 = new float[vertices.length * 2];
        int i = 0;
        int j = 0;
        while (i < vertices.length * 2) {
            verts2[i] = vertices[j].x;
            verts2[i + 1] = vertices[j].y;
            i += 2;
            j++;
        }
        jniSet(this.addr, verts2, 0, verts2.length);
    }

    public void set(float[] vertices) {
        jniSet(this.addr, vertices, 0, vertices.length);
    }

    public void set(float[] vertices, int offset, int len) {
        jniSet(this.addr, vertices, offset, len);
    }

    public void setAsBox(float hx, float hy) {
        jniSetAsBox(this.addr, hx, hy);
    }

    public void setAsBox(float hx, float hy, Vector2 center, float angle) {
        jniSetAsBox(this.addr, hx, hy, center.x, center.y, angle);
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
}