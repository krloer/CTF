package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public class WorldManifold {
    protected int numContactPoints;
    protected final Vector2 normal = new Vector2();
    protected final Vector2[] points = {new Vector2(), new Vector2()};
    protected final float[] separations = new float[2];

    public Vector2 getNormal() {
        return this.normal;
    }

    public Vector2[] getPoints() {
        return this.points;
    }

    public float[] getSeparations() {
        return this.separations;
    }

    public int getNumberOfContactPoints() {
        return this.numContactPoints;
    }
}