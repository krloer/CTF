package com.badlogic.gdx.physics.box2d;

/* loaded from: classes.dex */
public class JointEdge {
    public final Joint joint;
    public final Body other;

    /* JADX INFO: Access modifiers changed from: protected */
    public JointEdge(Body other, Joint joint) {
        this.other = other;
        this.joint = joint;
    }
}