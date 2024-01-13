package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public abstract class Joint {
    protected long addr;
    protected JointEdge jointEdgeA;
    protected JointEdge jointEdgeB;
    private Object userData;
    private final World world;
    private final float[] tmp = new float[2];
    private final Vector2 anchorA = new Vector2();
    private final Vector2 anchorB = new Vector2();
    private final Vector2 reactionForce = new Vector2();

    private native void jniGetAnchorA(long j, float[] fArr);

    private native void jniGetAnchorB(long j, float[] fArr);

    private native long jniGetBodyA(long j);

    private native long jniGetBodyB(long j);

    private native boolean jniGetCollideConnected(long j);

    private native void jniGetReactionForce(long j, float f, float[] fArr);

    private native float jniGetReactionTorque(long j, float f);

    private native int jniGetType(long j);

    private native boolean jniIsActive(long j);

    /* JADX INFO: Access modifiers changed from: protected */
    public Joint(World world, long addr) {
        this.world = world;
        this.addr = addr;
    }

    public JointDef.JointType getType() {
        int type = jniGetType(this.addr);
        if (type > 0 && type < JointDef.JointType.valueTypes.length) {
            return JointDef.JointType.valueTypes[type];
        }
        return JointDef.JointType.Unknown;
    }

    public Body getBodyA() {
        return this.world.bodies.get(jniGetBodyA(this.addr));
    }

    public Body getBodyB() {
        return this.world.bodies.get(jniGetBodyB(this.addr));
    }

    public Vector2 getAnchorA() {
        jniGetAnchorA(this.addr, this.tmp);
        Vector2 vector2 = this.anchorA;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public Vector2 getAnchorB() {
        jniGetAnchorB(this.addr, this.tmp);
        Vector2 vector2 = this.anchorB;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public boolean getCollideConnected() {
        return jniGetCollideConnected(this.addr);
    }

    public Vector2 getReactionForce(float inv_dt) {
        jniGetReactionForce(this.addr, inv_dt, this.tmp);
        Vector2 vector2 = this.reactionForce;
        float[] fArr = this.tmp;
        vector2.x = fArr[0];
        vector2.y = fArr[1];
        return vector2;
    }

    public float getReactionTorque(float inv_dt) {
        return jniGetReactionTorque(this.addr, inv_dt);
    }

    public Object getUserData() {
        return this.userData;
    }

    public void setUserData(Object userData) {
        this.userData = userData;
    }

    public boolean isActive() {
        return jniIsActive(this.addr);
    }
}