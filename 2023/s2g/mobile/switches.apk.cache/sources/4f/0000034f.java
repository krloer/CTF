package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class FrictionJointDef extends JointDef {
    public final Vector2 localAnchorA = new Vector2();
    public final Vector2 localAnchorB = new Vector2();
    public float maxForce = 0.0f;
    public float maxTorque = 0.0f;

    public FrictionJointDef() {
        this.type = JointDef.JointType.FrictionJoint;
    }

    public void initialize(Body bodyA, Body bodyB, Vector2 anchor) {
        this.bodyA = bodyA;
        this.bodyB = bodyB;
        this.localAnchorA.set(bodyA.getLocalPoint(anchor));
        this.localAnchorB.set(bodyB.getLocalPoint(anchor));
    }
}