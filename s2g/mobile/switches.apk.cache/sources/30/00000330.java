package com.badlogic.gdx.physics.box2d;

/* loaded from: classes.dex */
public class ContactImpulse {
    long addr;
    final World world;
    float[] tmp = new float[2];
    final float[] normalImpulses = new float[2];
    final float[] tangentImpulses = new float[2];

    private native int jniGetCount(long j);

    private native void jniGetNormalImpulses(long j, float[] fArr);

    private native void jniGetTangentImpulses(long j, float[] fArr);

    /* JADX INFO: Access modifiers changed from: protected */
    public ContactImpulse(World world, long addr) {
        this.world = world;
        this.addr = addr;
    }

    public float[] getNormalImpulses() {
        jniGetNormalImpulses(this.addr, this.normalImpulses);
        return this.normalImpulses;
    }

    public float[] getTangentImpulses() {
        jniGetTangentImpulses(this.addr, this.tangentImpulses);
        return this.tangentImpulses;
    }

    public int getCount() {
        return jniGetCount(this.addr);
    }
}