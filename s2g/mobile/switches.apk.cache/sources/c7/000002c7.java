package com.badlogic.gdx.maps.tiled.objects;

import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.objects.TextureMapObject;
import com.badlogic.gdx.maps.tiled.TiledMapTile;

/* loaded from: classes.dex */
public class TiledMapTileMapObject extends TextureMapObject {
    private boolean flipHorizontally;
    private boolean flipVertically;
    private TiledMapTile tile;

    public TiledMapTileMapObject(TiledMapTile tile, boolean flipHorizontally, boolean flipVertically) {
        this.flipHorizontally = flipHorizontally;
        this.flipVertically = flipVertically;
        this.tile = tile;
        TextureRegion textureRegion = new TextureRegion(tile.getTextureRegion());
        textureRegion.flip(flipHorizontally, flipVertically);
        setTextureRegion(textureRegion);
    }

    public boolean isFlipHorizontally() {
        return this.flipHorizontally;
    }

    public void setFlipHorizontally(boolean flipHorizontally) {
        this.flipHorizontally = flipHorizontally;
    }

    public boolean isFlipVertically() {
        return this.flipVertically;
    }

    public void setFlipVertically(boolean flipVertically) {
        this.flipVertically = flipVertically;
    }

    public TiledMapTile getTile() {
        return this.tile;
    }

    public void setTile(TiledMapTile tile) {
        this.tile = tile;
    }
}