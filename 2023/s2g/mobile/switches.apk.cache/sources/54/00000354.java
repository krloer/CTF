package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class MouseJoint extends Joint {
    private final Vector2 target;
    final float[] tmp;

    private native float jniGetDampingRatio(long j);

    private native float jniGetFrequency(long j);

    private native float jniGetMaxForce(long j);

    private native void jniGetTarget(long j, float[] fArr);

    private native void jniSetDampingRatio(long j, float f);

    private native void jniSetFrequency(long j, float f);

    private native void jniSetMaxForce(long j, float f);

    private native void jniSetTarget(long j, float f, float f2);

    public MouseJoint(World world, long addr) {
        super(world, addr);
        this.tmp = new float[2];
        this.target = new Vector2();
    }

    public void setTarget(Vector2 target) {
        jniSetTarget(this.addr, target.x, target.y);
    }

    public Vector2 getTarget() {
        jniGetTarget(this.addr, this.tmp);
        Vector2 vector2 = this.target;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public void setMaxForce(float force) {
        jniSetMaxForce(this.addr, force);
    }

    public float getMaxForce() {
        return jniGetMaxForce(this.addr);
    }

    public void setFrequency(float hz) {
        jniSetFrequency(this.addr, hz);
    }

    public float getFrequency() {
        return jniGetFrequency(this.addr);
    }

    public void setDampingRatio(float ratio) {
        jniSetDampingRatio(this.addr, ratio);
    }

    public float getDampingRatio() {
        return jniGetDampingRatio(this.addr);
    }
}