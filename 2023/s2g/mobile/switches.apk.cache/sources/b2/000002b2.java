package com.badlogic.gdx.maps.objects;

import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.MapObject;

/* loaded from: classes.dex */
public class TextureMapObject extends MapObject {
    private float originX;
    private float originY;
    private float rotation;
    private float scaleX;
    private float scaleY;
    private TextureRegion textureRegion;
    private float x;
    private float y;

    public float getX() {
        return this.x;
    }

    public void setX(float x) {
        this.x = x;
    }

    public float getY() {
        return this.y;
    }

    public void setY(float y) {
        this.y = y;
    }

    public float getOriginX() {
        return this.originX;
    }

    public void setOriginX(float x) {
        this.originX = x;
    }

    public float getOriginY() {
        return this.originY;
    }

    public void setOriginY(float y) {
        this.originY = y;
    }

    public float getScaleX() {
        return this.scaleX;
    }

    public void setScaleX(float x) {
        this.scaleX = x;
    }

    public float getScaleY() {
        return this.scaleY;
    }

    public void setScaleY(float y) {
        this.scaleY = y;
    }

    public float getRotation() {
        return this.rotation;
    }

    public void setRotation(float rotation) {
        this.rotation = rotation;
    }

    public TextureRegion getTextureRegion() {
        return this.textureRegion;
    }

    public void setTextureRegion(TextureRegion region) {
        this.textureRegion = region;
    }

    public TextureMapObject() {
        this(null);
    }

    public TextureMapObject(TextureRegion textureRegion) {
        this.x = 0.0f;
        this.y = 0.0f;
        this.originX = 0.0f;
        this.originY = 0.0f;
        this.scaleX = 1.0f;
        this.scaleY = 1.0f;
        this.rotation = 0.0f;
        this.textureRegion = null;
        this.textureRegion = textureRegion;
    }
}