package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class RopeJoint extends Joint {
    private final Vector2 localAnchorA;
    private final Vector2 localAnchorB;
    private final float[] tmp;

    private native void jniGetLocalAnchorA(long j, float[] fArr);

    private native void jniGetLocalAnchorB(long j, float[] fArr);

    private native float jniGetMaxLength(long j);

    private native void jniSetMaxLength(long j, float f);

    public RopeJoint(World world, long addr) {
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

    public float getMaxLength() {
        return jniGetMaxLength(this.addr);
    }

    public void setMaxLength(float length) {
        jniSetMaxLength(this.addr, length);
    }
}