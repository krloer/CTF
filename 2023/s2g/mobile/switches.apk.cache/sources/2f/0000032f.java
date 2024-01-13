package com.badlogic.gdx.physics.box2d;

/* loaded from: classes.dex */
public interface ContactFilter {
    boolean shouldCollide(Fixture fixture, Fixture fixture2);
}