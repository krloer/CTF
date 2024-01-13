package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class PrismaticJointDef extends JointDef {
    public final Vector2 localAnchorA = new Vector2();
    public final Vector2 localAnchorB = new Vector2();
    public final Vector2 localAxisA = new Vector2(1.0f, 0.0f);
    public float referenceAngle = 0.0f;
    public boolean enableLimit = false;
    public float lowerTranslation = 0.0f;
    public float upperTranslation = 0.0f;
    public boolean enableMotor = false;
    public float maxMotorForce = 0.0f;
    public float motorSpeed = 0.0f;

    public PrismaticJointDef() {
        this.type = JointDef.JointType.PrismaticJoint;
    }

    public void initialize(Body bodyA, Body bodyB, Vector2 anchor, Vector2 axis) {
        this.bodyA = bodyA;
        this.bodyB = bodyB;
        this.localAnchorA.set(bodyA.getLocalPoint(anchor));
        this.localAnchorB.set(bodyB.getLocalPoint(anchor));
        this.localAxisA.set(bodyA.getLocalVector(axis));
        this.referenceAngle = bodyB.getAngle() - bodyA.getAngle();
    }
}