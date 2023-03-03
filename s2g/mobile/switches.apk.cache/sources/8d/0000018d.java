package com.badlogic.gdx.graphics.g3d.environment;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class SpotLight extends BaseLight<SpotLight> {
    public float cutoffAngle;
    public float exponent;
    public float intensity;
    public final Vector3 position = new Vector3();
    public final Vector3 direction = new Vector3();

    public SpotLight setPosition(float positionX, float positionY, float positionZ) {
        this.position.set(positionX, positionY, positionZ);
        return this;
    }

    public SpotLight setPosition(Vector3 position) {
        this.position.set(position);
        return this;
    }

    public SpotLight setDirection(float directionX, float directionY, float directionZ) {
        this.direction.set(directionX, directionY, directionZ);
        return this;
    }

    public SpotLight setDirection(Vector3 direction) {
        this.direction.set(direction);
        return this;
    }

    public SpotLight setIntensity(float intensity) {
        this.intensity = intensity;
        return this;
    }

    public SpotLight setCutoffAngle(float cutoffAngle) {
        this.cutoffAngle = cutoffAngle;
        return this;
    }

    public SpotLight setExponent(float exponent) {
        this.exponent = exponent;
        return this;
    }

    public SpotLight set(SpotLight copyFrom) {
        return set(copyFrom.color, copyFrom.position, copyFrom.direction, copyFrom.intensity, copyFrom.cutoffAngle, copyFrom.exponent);
    }

    public SpotLight set(Color color, Vector3 position, Vector3 direction, float intensity, float cutoffAngle, float exponent) {
        if (color != null) {
            this.color.set(color);
        }
        if (position != null) {
            this.position.set(position);
        }
        if (direction != null) {
            this.direction.set(direction).nor();
        }
        this.intensity = intensity;
        this.cutoffAngle = cutoffAngle;
        this.exponent = exponent;
        return this;
    }

    public SpotLight set(float r, float g, float b, Vector3 position, Vector3 direction, float intensity, float cutoffAngle, float exponent) {
        this.color.set(r, g, b, 1.0f);
        if (position != null) {
            this.position.set(position);
        }
        if (direction != null) {
            this.direction.set(direction).nor();
        }
        this.intensity = intensity;
        this.cutoffAngle = cutoffAngle;
        this.exponent = exponent;
        return this;
    }

    public SpotLight set(Color color, float posX, float posY, float posZ, float dirX, float dirY, float dirZ, float intensity, float cutoffAngle, float exponent) {
        if (color != null) {
            this.color.set(color);
        }
        this.position.set(posX, posY, posZ);
        this.direction.set(dirX, dirY, dirZ).nor();
        this.intensity = intensity;
        this.cutoffAngle = cutoffAngle;
        this.exponent = exponent;
        return this;
    }

    public SpotLight set(float r, float g, float b, float posX, float posY, float posZ, float dirX, float dirY, float dirZ, float intensity, float cutoffAngle, float exponent) {
        this.color.set(r, g, b, 1.0f);
        this.position.set(posX, posY, posZ);
        this.direction.set(dirX, dirY, dirZ).nor();
        this.intensity = intensity;
        this.cutoffAngle = cutoffAngle;
        this.exponent = exponent;
        return this;
    }

    public SpotLight setTarget(Vector3 target) {
        this.direction.set(target).sub(this.position).nor();
        return this;
    }

    public boolean equals(Object obj) {
        return (obj instanceof SpotLight) && equals((SpotLight) obj);
    }

    public boolean equals(SpotLight other) {
        return other != null && (other == this || (this.color.equals(other.color) && this.position.equals(other.position) && this.direction.equals(other.direction) && MathUtils.isEqual(this.intensity, other.intensity) && MathUtils.isEqual(this.cutoffAngle, other.cutoffAngle) && MathUtils.isEqual(this.exponent, other.exponent)));
    }
}