package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class MotorJointDef extends JointDef {
    public final Vector2 linearOffset = new Vector2();
    public float angularOffset = 0.0f;
    public float maxForce = 1.0f;
    public float maxTorque = 1.0f;
    public float correctionFactor = 0.3f;

    public MotorJointDef() {
        this.type = JointDef.JointType.MotorJoint;
    }

    public void initialize(Body body1, Body body2) {
        this.bodyA = body1;
        this.bodyB = body2;
        this.linearOffset.set(this.bodyA.getLocalPoint(this.bodyB.getPosition()));
        this.angularOffset = this.bodyB.getAngle() - this.bodyA.getAngle();
    }
}