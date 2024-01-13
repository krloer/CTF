package com.badlogic.gdx.maps;

import com.badlogic.gdx.utils.GdxRuntimeException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class MapLayer {
    private float offsetX;
    private float offsetY;
    private MapLayer parent;
    private float renderOffsetX;
    private float renderOffsetY;
    private String name = BuildConfig.FLAVOR;
    private float opacity = 1.0f;
    private boolean visible = true;
    private boolean renderOffsetDirty = true;
    private MapObjects objects = new MapObjects();
    private MapProperties properties = new MapProperties();

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public float getOpacity() {
        return this.opacity;
    }

    public void setOpacity(float opacity) {
        this.opacity = opacity;
    }

    public float getOffsetX() {
        return this.offsetX;
    }

    public void setOffsetX(float offsetX) {
        this.offsetX = offsetX;
        invalidateRenderOffset();
    }

    public float getOffsetY() {
        return this.offsetY;
    }

    public void setOffsetY(float offsetY) {
        this.offsetY = offsetY;
        invalidateRenderOffset();
    }

    public float getRenderOffsetX() {
        if (this.renderOffsetDirty) {
            calculateRenderOffsets();
        }
        return this.renderOffsetX;
    }

    public float getRenderOffsetY() {
        if (this.renderOffsetDirty) {
            calculateRenderOffsets();
        }
        return this.renderOffsetY;
    }

    public void invalidateRenderOffset() {
        this.renderOffsetDirty = true;
    }

    public MapLayer getParent() {
        return this.parent;
    }

    public void setParent(MapLayer parent) {
        if (parent == this) {
            throw new GdxRuntimeException("Can't set self as the parent");
        }
        this.parent = parent;
    }

    public MapObjects getObjects() {
        return this.objects;
    }

    public boolean isVisible() {
        return this.visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public MapProperties getProperties() {
        return this.properties;
    }

    protected void calculateRenderOffsets() {
        MapLayer mapLayer = this.parent;
        if (mapLayer != null) {
            mapLayer.calculateRenderOffsets();
            this.renderOffsetX = this.parent.getRenderOffsetX() + this.offsetX;
            this.renderOffsetY = this.parent.getRenderOffsetY() + this.offsetY;
        } else {
            this.renderOffsetX = this.offsetX;
            this.renderOffsetY = this.offsetY;
        }
        this.renderOffsetDirty = false;
    }
}