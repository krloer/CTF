package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class WeldJoint extends Joint {
    private final Vector2 localAnchorA;
    private final Vector2 localAnchorB;
    private final float[] tmp;

    private native float jniGetDampingRatio(long j);

    private native float jniGetFrequency(long j);

    private native void jniGetLocalAnchorA(long j, float[] fArr);

    private native void jniGetLocalAnchorB(long j, float[] fArr);

    private native float jniGetReferenceAngle(long j);

    private native void jniSetDampingRatio(long j, float f);

    private native void jniSetFrequency(long j, float f);

    public WeldJoint(World world, long addr) {
        super(world, addr);
        this.tmp = new float[2];
        this.localAnchorA = new Vector2();
        this.localAnchorB = new Vector2();
    }

    public Vector2 getLocalAnchorA() {
        jniGetLocalAnchorA(this.addr, this.tmp);
        Vector2 vector2 = this.localAnchorA;
        float[] fArr = this.tmp;
        vector2.set(fArr[0], fArr[1]);
        return this.localAnchorA;
    }

    public Vector2 getLocalAnchorB() {
        jniGetLocalAnchorB(this.addr, this.tmp);
        Vector2 vector2 = this.localAnchorB;
        float[] fArr = this.tmp;
        vector2.set(fArr[0], fArr[1]);
        return this.localAnchorB;
    }

    public float getReferenceAngle() {
        return jniGetReferenceAngle(this.addr);
    }

    public float getFrequency() {
        return jniGetFrequency(this.addr);
    }

    public void setFrequency(float hz) {
        jniSetFrequency(this.addr, hz);
    }

    public float getDampingRatio() {
        return jniGetDampingRatio(this.addr);
    }

    public void setDampingRatio(float ratio) {
        jniSetDampingRatio(this.addr, ratio);
    }
}