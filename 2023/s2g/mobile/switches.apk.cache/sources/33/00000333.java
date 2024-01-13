package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Shape;

/* loaded from: classes.dex */
public class EdgeShape extends Shape {
    static final float[] vertex = new float[2];

    private native void jniGetVertex0(long j, float[] fArr);

    private native void jniGetVertex1(long j, float[] fArr);

    private native void jniGetVertex2(long j, float[] fArr);

    private native void jniGetVertex3(long j, float[] fArr);

    private native boolean jniHasVertex0(long j);

    private native boolean jniHasVertex3(long j);

    private native void jniSet(long j, float f, float f2, float f3, float f4);

    private native void jniSetHasVertex0(long j, boolean z);

    private native void jniSetHasVertex3(long j, boolean z);

    private native void jniSetVertex0(long j, float f, float f2);

    private native void jniSetVertex3(long j, float f, float f2);

    private native long newEdgeShape();

    public EdgeShape() {
        this.addr = newEdgeShape();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EdgeShape(long addr) {
        this.addr = addr;
    }

    public void set(Vector2 v1, Vector2 v2) {
        set(v1.x, v1.y, v2.x, v2.y);
    }

    public void set(float v1X, float v1Y, float v2X, float v2Y) {
        jniSet(this.addr, v1X, v1Y, v2X, v2Y);
    }

    public void getVertex1(Vector2 vec) {
        jniGetVertex1(this.addr, vertex);
        float[] fArr = vertex;
        vec.x = fArr[0];
        vec.y = fArr[1];
    }

    public void getVertex2(Vector2 vec) {
        jniGetVertex2(this.addr, vertex);
        float[] fArr = vertex;
        vec.x = fArr[0];
        vec.y = fArr[1];
    }

    public void getVertex0(Vector2 vec) {
        jniGetVertex0(this.addr, vertex);
        float[] fArr = vertex;
        vec.x = fArr[0];
        vec.y = fArr[1];
    }

    public void setVertex0(Vector2 vec) {
        jniSetVertex0(this.addr, vec.x, vec.y);
    }

    public void setVertex0(float x, float y) {
        jniSetVertex0(this.addr, x, y);
    }

    public void getVertex3(Vector2 vec) {
        jniGetVertex3(this.addr, vertex);
        float[] fArr = vertex;
        vec.x = fArr[0];
        vec.y = fArr[1];
    }

    public void setVertex3(Vector2 vec) {
        jniSetVertex3(this.addr, vec.x, vec.y);
    }

    public void setVertex3(float x, float y) {
        jniSetVertex3(this.addr, x, y);
    }

    public boolean hasVertex0() {
        return jniHasVertex0(this.addr);
    }

    public void setHasVertex0(boolean hasVertex0) {
        jniSetHasVertex0(this.addr, hasVertex0);
    }

    public boolean hasVertex3() {
        return jniHasVertex3(this.addr);
    }

    public void setHasVertex3(boolean hasVertex3) {
        jniSetHasVertex3(this.addr, hasVertex3);
    }

    @Override // com.badlogic.gdx.physics.box2d.Shape
    public Shape.Type getType() {
        return Shape.Type.Edge;
    }
}