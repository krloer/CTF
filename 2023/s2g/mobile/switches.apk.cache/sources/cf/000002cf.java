package com.badlogic.gdx.maps.tiled.tiles;

import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.MapObjects;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.TiledMapTile;

/* loaded from: classes.dex */
public class StaticTiledMapTile implements TiledMapTile {
    private TiledMapTile.BlendMode blendMode = TiledMapTile.BlendMode.ALPHA;
    private int id;
    private MapObjects objects;
    private float offsetX;
    private float offsetY;
    private MapProperties properties;
    private TextureRegion textureRegion;

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public int getId() {
        return this.id;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setId(int id) {
        this.id = id;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public TiledMapTile.BlendMode getBlendMode() {
        return this.blendMode;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setBlendMode(TiledMapTile.BlendMode blendMode) {
        this.blendMode = blendMode;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public MapProperties getProperties() {
        if (this.properties == null) {
            this.properties = new MapProperties();
        }
        return this.properties;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public MapObjects getObjects() {
        if (this.objects == null) {
            this.objects = new MapObjects();
        }
        return this.objects;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public TextureRegion getTextureRegion() {
        return this.textureRegion;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setTextureRegion(TextureRegion textureRegion) {
        this.textureRegion = textureRegion;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public float getOffsetX() {
        return this.offsetX;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setOffsetX(float offsetX) {
        this.offsetX = offsetX;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public float getOffsetY() {
        return this.offsetY;
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setOffsetY(float offsetY) {
        this.offsetY = offsetY;
    }

    public StaticTiledMapTile(TextureRegion textureRegion) {
        this.textureRegion = textureRegion;
    }

    public StaticTiledMapTile(StaticTiledMapTile copy) {
        if (copy.properties != null) {
            getProperties().putAll(copy.properties);
        }
        this.objects = copy.objects;
        this.textureRegion = copy.textureRegion;
        this.id = copy.id;
    }
}