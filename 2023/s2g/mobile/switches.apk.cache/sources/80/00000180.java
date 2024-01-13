package com.badlogic.gdx.graphics.g3d.decals;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

/* loaded from: classes.dex */
public class DecalMaterial {
    public static final int NO_BLEND = -1;
    protected int dstBlendFactor;
    protected int srcBlendFactor;
    protected TextureRegion textureRegion;

    public void set() {
        this.textureRegion.getTexture().bind(0);
        if (!isOpaque()) {
            Gdx.gl.glBlendFunc(this.srcBlendFactor, this.dstBlendFactor);
        }
    }

    public boolean isOpaque() {
        return this.srcBlendFactor == -1;
    }

    public int getSrcBlendFactor() {
        return this.srcBlendFactor;
    }

    public int getDstBlendFactor() {
        return this.dstBlendFactor;
    }

    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        DecalMaterial material = (DecalMaterial) o;
        return this.dstBlendFactor == material.dstBlendFactor && this.srcBlendFactor == material.srcBlendFactor && this.textureRegion.getTexture() == material.textureRegion.getTexture();
    }

    public int hashCode() {
        int result = this.textureRegion.getTexture() != null ? this.textureRegion.getTexture().hashCode() : 0;
        return (((result * 31) + this.srcBlendFactor) * 31) + this.dstBlendFactor;
    }
}