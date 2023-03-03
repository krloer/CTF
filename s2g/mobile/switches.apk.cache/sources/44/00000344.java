package com.badlogic.gdx.physics.box2d;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public class Transform {
    public static final int COS = 2;
    public static final int POS_X = 0;
    public static final int POS_Y = 1;
    public static final int SIN = 3;
    private Vector2 orientation;
    private Vector2 position;
    public float[] vals;

    public Transform() {
        this.vals = new float[4];
        this.position = new Vector2();
        this.orientation = new Vector2();
    }

    public Transform(Vector2 position, float angle) {
        this.vals = new float[4];
        this.position = new Vector2();
        this.orientation = new Vector2();
        setPosition(position);
        setRotation(angle);
    }

    public Transform(Vector2 position, Vector2 orientation) {
        this.vals = new float[4];
        this.position = new Vector2();
        this.orientation = new Vector2();
        setPosition(position);
        setOrientation(orientation);
    }

    public Vector2 mul(Vector2 v) {
        float[] fArr = this.vals;
        float x = fArr[0] + (fArr[2] * v.x) + ((-this.vals[3]) * v.y);
        float[] fArr2 = this.vals;
        float y = fArr2[1] + (fArr2[3] * v.x) + (this.vals[2] * v.y);
        v.x = x;
        v.y = y;
        return v;
    }

    public Vector2 getPosition() {
        Vector2 vector2 = this.position;
        float[] fArr = this.vals;
        return vector2.set(fArr[0], fArr[1]);
    }

    public void setRotation(float angle) {
        float c = (float) Math.cos(angle);
        float s = (float) Math.sin(angle);
        float[] fArr = this.vals;
        fArr[2] = c;
        fArr[3] = s;
    }

    public float getRotation() {
        float[] fArr = this.vals;
        return (float) Math.atan2(fArr[3], fArr[2]);
    }

    public Vector2 getOrientation() {
        Vector2 vector2 = this.orientation;
        float[] fArr = this.vals;
        return vector2.set(fArr[2], fArr[3]);
    }

    public void setOrientation(Vector2 orientation) {
        this.vals[2] = orientation.x;
        this.vals[3] = orientation.y;
    }

    public void setPosition(Vector2 pos) {
        this.vals[0] = pos.x;
        this.vals[1] = pos.y;
    }
}