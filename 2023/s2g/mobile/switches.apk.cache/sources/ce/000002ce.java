package com.badlogic.gdx.maps.tiled.tiles;

import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.MapObjects;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.TiledMapTile;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.TimeUtils;

/* loaded from: classes.dex */
public class AnimatedTiledMapTile implements TiledMapTile {
    private int[] animationIntervals;
    private TiledMapTile.BlendMode blendMode;
    private int frameCount;
    private StaticTiledMapTile[] frameTiles;
    private int id;
    private int loopDuration;
    private MapObjects objects;
    private MapProperties properties;
    private static long lastTiledMapRenderTime = 0;
    private static final long initialTimeOffset = TimeUtils.millis();

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

    public int getCurrentFrameIndex() {
        int currentTime = (int) (lastTiledMapRenderTime % this.loopDuration);
        int i = 0;
        while (true) {
            int[] iArr = this.animationIntervals;
            if (i < iArr.length) {
                int animationInterval = iArr[i];
                if (currentTime <= animationInterval) {
                    return i;
                }
                currentTime -= animationInterval;
                i++;
            } else {
                throw new GdxRuntimeException("Could not determine current animation frame in AnimatedTiledMapTile.  This should never happen.");
            }
        }
    }

    public TiledMapTile getCurrentFrame() {
        return this.frameTiles[getCurrentFrameIndex()];
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public TextureRegion getTextureRegion() {
        return getCurrentFrame().getTextureRegion();
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setTextureRegion(TextureRegion textureRegion) {
        throw new GdxRuntimeException("Cannot set the texture region of AnimatedTiledMapTile.");
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public float getOffsetX() {
        return getCurrentFrame().getOffsetX();
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setOffsetX(float offsetX) {
        throw new GdxRuntimeException("Cannot set offset of AnimatedTiledMapTile.");
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public float getOffsetY() {
        return getCurrentFrame().getOffsetY();
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapTile
    public void setOffsetY(float offsetY) {
        throw new GdxRuntimeException("Cannot set offset of AnimatedTiledMapTile.");
    }

    public int[] getAnimationIntervals() {
        return this.animationIntervals;
    }

    public void setAnimationIntervals(int[] intervals) {
        if (intervals.length == this.animationIntervals.length) {
            this.animationIntervals = intervals;
            this.loopDuration = 0;
            for (int i : intervals) {
                this.loopDuration += i;
            }
            return;
        }
        throw new GdxRuntimeException("Cannot set " + intervals.length + " frame intervals. The given int[] must have a size of " + this.animationIntervals.length + ".");
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

    public static void updateAnimationBaseTime() {
        lastTiledMapRenderTime = TimeUtils.millis() - initialTimeOffset;
    }

    public AnimatedTiledMapTile(float interval, Array<StaticTiledMapTile> frameTiles) {
        this.blendMode = TiledMapTile.BlendMode.ALPHA;
        this.frameCount = 0;
        this.frameTiles = new StaticTiledMapTile[frameTiles.size];
        this.frameCount = frameTiles.size;
        this.loopDuration = frameTiles.size * ((int) (interval * 1000.0f));
        this.animationIntervals = new int[frameTiles.size];
        for (int i = 0; i < frameTiles.size; i++) {
            this.frameTiles[i] = frameTiles.get(i);
            this.animationIntervals[i] = (int) (interval * 1000.0f);
        }
    }

    public AnimatedTiledMapTile(IntArray intervals, Array<StaticTiledMapTile> frameTiles) {
        this.blendMode = TiledMapTile.BlendMode.ALPHA;
        this.frameCount = 0;
        this.frameTiles = new StaticTiledMapTile[frameTiles.size];
        this.frameCount = frameTiles.size;
        this.animationIntervals = intervals.toArray();
        this.loopDuration = 0;
        for (int i = 0; i < intervals.size; i++) {
            this.frameTiles[i] = frameTiles.get(i);
            this.loopDuration += intervals.get(i);
        }
    }

    public StaticTiledMapTile[] getFrameTiles() {
        return this.frameTiles;
    }
}