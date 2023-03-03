package com.badlogic.gdx.physics.box2d.joints;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.physics.box2d.JointDef;

/* loaded from: classes.dex */
public class RopeJointDef extends JointDef {
    public final Vector2 localAnchorA = new Vector2(-1.0f, 0.0f);
    public final Vector2 localAnchorB = new Vector2(1.0f, 0.0f);
    public float maxLength = 0.0f;

    public RopeJointDef() {
        this.type = JointDef.JointType.RopeJoint;
    }
}