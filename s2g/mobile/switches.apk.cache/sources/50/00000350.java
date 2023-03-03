package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.physics.box2d.Joint;
import com.badlogic.gdx.physics.box2d.World;

/* loaded from: classes.dex */
public class GearJoint extends Joint {
    private Joint joint1;
    private Joint joint2;

    private native long jniGetJoint1(long j);

    private native long jniGetJoint2(long j);

    private native float jniGetRatio(long j);

    private native void jniSetRatio(long j, float f);

    public GearJoint(World world, long addr, Joint joint1, Joint joint2) {
        super(world, addr);
        this.joint1 = joint1;
        this.joint2 = joint2;
    }

    public Joint getJoint1() {
        return this.joint1;
    }

    public Joint getJoint2() {
        return this.joint2;
    }

    public void setRatio(float ratio) {
        jniSetRatio(this.addr, ratio);
    }

    public float getRatio() {
        return jniGetRatio(this.addr);
    }
}