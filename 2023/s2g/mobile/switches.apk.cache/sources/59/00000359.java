package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.Body;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class PulleyJointDef extends JointDef {
    private static final float minPulleyLength = 2.0f;
    public final Vector2 groundAnchorA = new Vector2(-1.0f, 1.0f);
    public final Vector2 groundAnchorB = new Vector2(1.0f, 1.0f);
    public final Vector2 localAnchorA = new Vector2(-1.0f, 0.0f);
    public final Vector2 localAnchorB = new Vector2(1.0f, 0.0f);
    public float lengthA = 0.0f;
    public float lengthB = 0.0f;
    public float ratio = 1.0f;

    public PulleyJointDef() {
        this.type = JointDef.JointType.PulleyJoint;
        this.collideConnected = true;
    }

    public void initialize(Body bodyA, Body bodyB, Vector2 groundAnchorA, Vector2 groundAnchorB, Vector2 anchorA, Vector2 anchorB, float ratio) {
        this.bodyA = bodyA;
        this.bodyB = bodyB;
        this.groundAnchorA.set(groundAnchorA);
        this.groundAnchorB.set(groundAnchorB);
        this.localAnchorA.set(bodyA.getLocalPoint(anchorA));
        this.localAnchorB.set(bodyB.getLocalPoint(anchorB));
        this.lengthA = anchorA.dst(groundAnchorA);
        this.lengthB = anchorB.dst(groundAnchorB);
        this.ratio = ratio;
        float f = this.lengthA + (this.lengthB * ratio);
    }
}