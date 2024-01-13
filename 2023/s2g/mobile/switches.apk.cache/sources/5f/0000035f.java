package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class WeldJointDef extends JointDef {
    public final Vector2 localAnchorA = new Vector2();
    public final Vector2 localAnchorB = new Vector2();
    public float referenceAngle = 0.0f;
    public float frequencyHz = 0.0f;
    public float dampingRatio = 0.0f;

    public WeldJointDef() {
        this.type = JointDef.JointType.WeldJoint;
    }

    public void initialize(Body body1, Body body2, Vector2 anchor) {
        this.bodyA = body1;
        this.bodyB = body2;
        this.localAnchorA.set(body1.getLocalPoint(anchor));
        this.localAnchorB.set(body2.getLocalPoint(anchor));
        this.referenceAngle = body2.getAngle() - body1.getAngle();
    }
}