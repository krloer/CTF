package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class RevoluteJointDef extends JointDef {
    public final Vector2 localAnchorA = new Vector2();
    public final Vector2 localAnchorB = new Vector2();
    public float referenceAngle = 0.0f;
    public boolean enableLimit = false;
    public float lowerAngle = 0.0f;
    public float upperAngle = 0.0f;
    public boolean enableMotor = false;
    public float motorSpeed = 0.0f;
    public float maxMotorTorque = 0.0f;

    public RevoluteJointDef() {
        this.type = JointDef.JointType.RevoluteJoint;
    }

    public void initialize(Body bodyA, Body bodyB, Vector2 anchor) {
        this.bodyA = bodyA;
        this.bodyB = bodyB;
        this.localAnchorA.set(bodyA.getLocalPoint(anchor));
        this.localAnchorB.set(bodyB.getLocalPoint(anchor));
        this.referenceAngle = bodyB.getAngle() - bodyA.getAngle();
    }
}