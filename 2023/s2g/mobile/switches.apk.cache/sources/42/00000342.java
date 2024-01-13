package com.badlogic.gdx.physics.box2d;

/* loaded from: classes.dex */
public abstract class Shape {
    protected long addr;

    /* loaded from: classes.dex */
    public enum Type {
        Circle,
        Edge,
        Polygon,
        Chain
    }

    private native void jniDispose(long j);

    private native int jniGetChildCount(long j);

    private native float jniGetRadius(long j);

    /* JADX INFO: Access modifiers changed from: protected */
    public static native int jniGetType(long j);

    private native void jniSetRadius(long j, float f);

    public abstract Type getType();

    public float getRadius() {
        return jniGetRadius(this.addr);
    }

    public void setRadius(float radius) {
        jniSetRadius(this.addr, radius);
    }

    public void dispose() {
        jniDispose(this.addr);
    }

    public int getChildCount() {
        return jniGetChildCount(this.addr);
    }
}