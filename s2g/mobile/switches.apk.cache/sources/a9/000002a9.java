package com.badlogic.gdx.maps;

import com.badlogic.gdx.graphics.Color;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class MapObject {
    private String name = BuildConfig.FLAVOR;
    private float opacity = 1.0f;
    private boolean visible = true;
    private MapProperties properties = new MapProperties();
    private Color color = Color.WHITE.cpy();

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Color getColor() {
        return this.color;
    }

    public void setColor(Color color) {
        this.color = color;
    }

    public float getOpacity() {
        return this.opacity;
    }

    public void setOpacity(float opacity) {
        this.opacity = opacity;
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
}