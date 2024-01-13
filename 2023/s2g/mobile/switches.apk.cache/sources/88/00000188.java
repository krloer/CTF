package com.badlogic.gdx.graphics.g3d.environment;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class DirectionalLight extends BaseLight<DirectionalLight> {
    public final Vector3 direction = new Vector3();

    public DirectionalLight setDirection(float directionX, float directionY, float directionZ) {
        this.direction.set(directionX, directionY, directionZ);
        return this;
    }

    public DirectionalLight setDirection(Vector3 direction) {
        this.direction.set(direction);
        return this;
    }

    public DirectionalLight set(DirectionalLight copyFrom) {
        return set(copyFrom.color, copyFrom.direction);
    }

    public DirectionalLight set(Color color, Vector3 direction) {
        if (color != null) {
            this.color.set(color);
        }
        if (direction != null) {
            this.direction.set(direction).nor();
        }
        return this;
    }

    public DirectionalLight set(float r, float g, float b, Vector3 direction) {
        this.color.set(r, g, b, 1.0f);
        if (direction != null) {
            this.direction.set(direction).nor();
        }
        return this;
    }

    public DirectionalLight set(Color color, float dirX, float dirY, float dirZ) {
        if (color != null) {
            this.color.set(color);
        }
        this.direction.set(dirX, dirY, dirZ).nor();
        return this;
    }

    public DirectionalLight set(float r, float g, float b, float dirX, float dirY, float dirZ) {
        this.color.set(r, g, b, 1.0f);
        this.direction.set(dirX, dirY, dirZ).nor();
        return this;
    }

    public boolean equals(Object arg0) {
        return (arg0 instanceof DirectionalLight) && equals((DirectionalLight) arg0);
    }

    public boolean equals(DirectionalLight other) {
        return other != null && (other == this || (this.color.equals(other.color) && this.direction.equals(other.direction)));
    }
}