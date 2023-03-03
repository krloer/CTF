package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class PulleyJoint extends Joint {
    private final Vector2 groundAnchorA;
    private final Vector2 groundAnchorB;
    private final float[] tmp;

    private native void jniGetGroundAnchorA(long j, float[] fArr);

    private native void jniGetGroundAnchorB(long j, float[] fArr);

    private native float jniGetLength1(long j);

    private native float jniGetLength2(long j);

    private native float jniGetRatio(long j);

    public PulleyJoint(World world, long addr) {
        super(world, addr);
        this.tmp = new float[2];
        this.groundAnchorA = new Vector2();
        this.groundAnchorB = new Vector2();
    }

    public Vector2 getGroundAnchorA() {
        jniGetGroundAnchorA(this.addr, this.tmp);
        Vector2 vector2 = this.groundAnchorA;
        float[] fArr = this.tmp;
        vector2.set(fArr[0], fArr[1]);
        return this.groundAnchorA;
    }

    public Vector2 getGroundAnchorB() {
        jniGetGroundAnchorB(this.addr, this.tmp);
        Vector2 vector2 = this.groundAnchorB;
        float[] fArr = this.tmp;
        vector2.set(fArr[0], fArr[1]);
        return this.groundAnchorB;
    }

    public float getLength1() {
        return jniGetLength1(this.addr);
    }

    public float getLength2() {
        return jniGetLength2(this.addr);
    }

    public float getRatio() {
        return jniGetRatio(this.addr);
    }
}