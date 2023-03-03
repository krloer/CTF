package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class PrismaticJoint extends Joint {
    private final Vector2 localAnchorA;
    private final Vector2 localAnchorB;
    private final Vector2 localAxisA;
    private final float[] tmp;

    private native void jniEnableLimit(long j, boolean z);

    private native void jniEnableMotor(long j, boolean z);

    private native float jniGetJointSpeed(long j);

    private native float jniGetJointTranslation(long j);

    private native void jniGetLocalAnchorA(long j, float[] fArr);

    private native void jniGetLocalAnchorB(long j, float[] fArr);

    private native void jniGetLocalAxisA(long j, float[] fArr);

    private native float jniGetLowerLimit(long j);

    private native float jniGetMaxMotorForce(long j);

    private native float jniGetMotorForce(long j, float f);

    private native float jniGetMotorSpeed(long j);

    private native float jniGetReferenceAngle(long j);

    private native float jniGetUpperLimit(long j);

    private native boolean jniIsLimitEnabled(long j);

    private native boolean jniIsMotorEnabled(long j);

    private native void jniSetLimits(long j, float f, float f2);

    private native void jniSetMaxMotorForce(long j, float f);

    private native void jniSetMotorSpeed(long j, float f);

    public PrismaticJoint(World world, long addr) {
        super(world, addr);
        this.tmp = new float[2];
        this.localAnchorA = new Vector2();
        this.localAnchorB = new Vector2();
        this.localAxisA = new Vector2();
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

    public Vector2 getLocalAxisA() {
        jniGetLocalAxisA(this.addr, this.tmp);
        Vector2 vector2 = this.localAxisA;
        float[] fArr = this.tmp;
        vector2.set(fArr[0], fArr[1]);
        return this.localAxisA;
    }

    public float getJointTranslation() {
        return jniGetJointTranslation(this.addr);
    }

    public float getJointSpeed() {
        return jniGetJointSpeed(this.addr);
    }

    public boolean isLimitEnabled() {
        return jniIsLimitEnabled(this.addr);
    }

    public void enableLimit(boolean flag) {
        jniEnableLimit(this.addr, flag);
    }

    public float getLowerLimit() {
        return jniGetLowerLimit(this.addr);
    }

    public float getUpperLimit() {
        return jniGetUpperLimit(this.addr);
    }

    public void setLimits(float lower, float upper) {
        jniSetLimits(this.addr, lower, upper);
    }

    public boolean isMotorEnabled() {
        return jniIsMotorEnabled(this.addr);
    }

    public void enableMotor(boolean flag) {
        jniEnableMotor(this.addr, flag);
    }

    public void setMotorSpeed(float speed) {
        jniSetMotorSpeed(this.addr, speed);
    }

    public float getMotorSpeed() {
        return jniGetMotorSpeed(this.addr);
    }

    public void setMaxMotorForce(float force) {
        jniSetMaxMotorForce(this.addr, force);
    }

    public float getMotorForce(float invDt) {
        return jniGetMotorForce(this.addr, invDt);
    }

    public float getMaxMotorForce() {
        return jniGetMaxMotorForce(this.addr);
    }

    public float getReferenceAngle() {
        return jniGetReferenceAngle(this.addr);
    }
}