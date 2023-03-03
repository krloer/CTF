package com.badlogic.gdx.maps.tiled.renderers;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.SpriteCache;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.MapLayer;
import com.badlogic.gdx.maps.MapLayers;
import com.badlogic.gdx.maps.MapObject;
import com.badlogic.gdx.maps.tiled.TiledMap;
import com.badlogic.gdx.maps.tiled.TiledMapImageLayer;
import com.badlogic.gdx.maps.tiled.TiledMapRenderer;
import com.badlogic.gdx.maps.tiled.TiledMapTile;
import com.badlogic.gdx.maps.tiled.TiledMapTileLayer;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.utils.Disposable;
import java.util.Iterator;

/* loaded from: classes.dex */
public class OrthoCachedTiledMapRenderer implements TiledMapRenderer, Disposable {
    protected static final int NUM_VERTICES = 20;
    private static final float tolerance = 1.0E-5f;
    protected boolean blending;
    protected final Rectangle cacheBounds;
    protected boolean cached;
    protected boolean canCacheMoreE;
    protected boolean canCacheMoreN;
    protected boolean canCacheMoreS;
    protected boolean canCacheMoreW;
    protected int count;
    protected final TiledMap map;
    protected float maxTileHeight;
    protected float maxTileWidth;
    protected float overCache;
    protected final SpriteCache spriteCache;
    protected float unitScale;
    protected final float[] vertices;
    protected final Rectangle viewBounds;

    public OrthoCachedTiledMapRenderer(TiledMap map) {
        this(map, 1.0f, 2000);
    }

    public OrthoCachedTiledMapRenderer(TiledMap map, float unitScale) {
        this(map, unitScale, 2000);
    }

    public OrthoCachedTiledMapRenderer(TiledMap map, float unitScale, int cacheSize) {
        this.vertices = new float[20];
        this.viewBounds = new Rectangle();
        this.cacheBounds = new Rectangle();
        this.overCache = 0.5f;
        this.map = map;
        this.unitScale = unitScale;
        this.spriteCache = new SpriteCache(cacheSize, true);
    }

    @Override // com.badlogic.gdx.maps.MapRenderer
    public void setView(OrthographicCamera camera) {
        this.spriteCache.setProjectionMatrix(camera.combined);
        float width = (camera.viewportWidth * camera.zoom) + (this.maxTileWidth * 2.0f * this.unitScale);
        float height = (camera.viewportHeight * camera.zoom) + (this.maxTileHeight * 2.0f * this.unitScale);
        this.viewBounds.set(camera.position.x - (width / 2.0f), camera.position.y - (height / 2.0f), width, height);
        if ((this.canCacheMoreW && this.viewBounds.x < this.cacheBounds.x - tolerance) || ((this.canCacheMoreS && this.viewBounds.y < this.cacheBounds.y - tolerance) || ((this.canCacheMoreE && this.viewBounds.x + this.viewBounds.width > this.cacheBounds.x + this.cacheBounds.width + tolerance) || (this.canCacheMoreN && this.viewBounds.y + this.viewBounds.height > this.cacheBounds.y + this.cacheBounds.height + tolerance)))) {
            this.cached = false;
        }
    }

    @Override // com.badlogic.gdx.maps.MapRenderer
    public void setView(Matrix4 projection, float x, float y, float width, float height) {
        this.spriteCache.setProjectionMatrix(projection);
        float f = this.maxTileWidth;
        float f2 = this.unitScale;
        float x2 = x - (f * f2);
        float f3 = this.maxTileHeight;
        this.viewBounds.set(x2, y - (f3 * f2), width + (f * 2.0f * f2), height + (f3 * 2.0f * f2));
        if ((this.canCacheMoreW && this.viewBounds.x < this.cacheBounds.x - tolerance) || ((this.canCacheMoreS && this.viewBounds.y < this.cacheBounds.y - tolerance) || ((this.canCacheMoreE && this.viewBounds.x + this.viewBounds.width > this.cacheBounds.x + this.cacheBounds.width + tolerance) || (this.canCacheMoreN && this.viewBounds.y + this.viewBounds.height > this.cacheBounds.y + this.cacheBounds.height + tolerance)))) {
            this.cached = false;
        }
    }

    @Override // com.badlogic.gdx.maps.MapRenderer
    public void render() {
        if (!this.cached) {
            this.cached = true;
            this.count = 0;
            this.spriteCache.clear();
            float extraWidth = this.viewBounds.width * this.overCache;
            float extraHeight = this.viewBounds.height * this.overCache;
            this.cacheBounds.x = this.viewBounds.x - extraWidth;
            this.cacheBounds.y = this.viewBounds.y - extraHeight;
            this.cacheBounds.width = this.viewBounds.width + (extraWidth * 2.0f);
            this.cacheBounds.height = this.viewBounds.height + (2.0f * extraHeight);
            Iterator<MapLayer> it = this.map.getLayers().iterator();
            while (it.hasNext()) {
                MapLayer layer = it.next();
                this.spriteCache.beginCache();
                if (layer instanceof TiledMapTileLayer) {
                    renderTileLayer((TiledMapTileLayer) layer);
                } else if (layer instanceof TiledMapImageLayer) {
                    renderImageLayer((TiledMapImageLayer) layer);
                }
                this.spriteCache.endCache();
            }
        }
        if (this.blending) {
            Gdx.gl.glEnable(GL20.GL_BLEND);
            Gdx.gl.glBlendFunc(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        this.spriteCache.begin();
        MapLayers mapLayers = this.map.getLayers();
        int j = mapLayers.getCount();
        for (int i = 0; i < j; i++) {
            MapLayer layer2 = mapLayers.get(i);
            if (layer2.isVisible()) {
                this.spriteCache.draw(i);
                renderObjects(layer2);
            }
        }
        this.spriteCache.end();
        if (this.blending) {
            Gdx.gl.glDisable(GL20.GL_BLEND);
        }
    }

    @Override // com.badlogic.gdx.maps.MapRenderer
    public void render(int[] layers) {
        if (!this.cached) {
            this.cached = true;
            this.count = 0;
            this.spriteCache.clear();
            float extraWidth = this.viewBounds.width * this.overCache;
            float extraHeight = this.viewBounds.height * this.overCache;
            this.cacheBounds.x = this.viewBounds.x - extraWidth;
            this.cacheBounds.y = this.viewBounds.y - extraHeight;
            this.cacheBounds.width = this.viewBounds.width + (extraWidth * 2.0f);
            this.cacheBounds.height = this.viewBounds.height + (2.0f * extraHeight);
            Iterator<MapLayer> it = this.map.getLayers().iterator();
            while (it.hasNext()) {
                MapLayer layer = it.next();
                this.spriteCache.beginCache();
                if (layer instanceof TiledMapTileLayer) {
                    renderTileLayer((TiledMapTileLayer) layer);
                } else if (layer instanceof TiledMapImageLayer) {
                    renderImageLayer((TiledMapImageLayer) layer);
                }
                this.spriteCache.endCache();
            }
        }
        if (this.blending) {
            Gdx.gl.glEnable(GL20.GL_BLEND);
            Gdx.gl.glBlendFunc(GL20.GL_SRC_ALPHA, GL20.GL_ONE_MINUS_SRC_ALPHA);
        }
        this.spriteCache.begin();
        MapLayers mapLayers = this.map.getLayers();
        for (int i : layers) {
            MapLayer layer2 = mapLayers.get(i);
            if (layer2.isVisible()) {
                this.spriteCache.draw(i);
                renderObjects(layer2);
            }
        }
        this.spriteCache.end();
        if (this.blending) {
            Gdx.gl.glDisable(GL20.GL_BLEND);
        }
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderObjects(MapLayer layer) {
        Iterator<MapObject> it = layer.getObjects().iterator();
        while (it.hasNext()) {
            MapObject object = it.next();
            renderObject(object);
        }
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderObject(MapObject object) {
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderTileLayer(TiledMapTileLayer layer) {
        int layerWidth;
        int layerHeight;
        int col1;
        int col2;
        float layerTileWidth;
        float layerTileHeight;
        float layerOffsetX;
        float layerOffsetY;
        int row1;
        float color;
        OrthoCachedTiledMapRenderer orthoCachedTiledMapRenderer = this;
        float color2 = Color.toFloatBits(1.0f, 1.0f, 1.0f, layer.getOpacity());
        int layerWidth2 = layer.getWidth();
        int layerHeight2 = layer.getHeight();
        float layerTileWidth2 = layer.getTileWidth() * orthoCachedTiledMapRenderer.unitScale;
        float layerTileHeight2 = layer.getTileHeight() * orthoCachedTiledMapRenderer.unitScale;
        float layerOffsetX2 = layer.getRenderOffsetX() * orthoCachedTiledMapRenderer.unitScale;
        float layerOffsetY2 = (-layer.getRenderOffsetY()) * orthoCachedTiledMapRenderer.unitScale;
        int col12 = Math.max(0, (int) ((orthoCachedTiledMapRenderer.cacheBounds.x - layerOffsetX2) / layerTileWidth2));
        int col22 = Math.min(layerWidth2, (int) ((((orthoCachedTiledMapRenderer.cacheBounds.x + orthoCachedTiledMapRenderer.cacheBounds.width) + layerTileWidth2) - layerOffsetX2) / layerTileWidth2));
        int row12 = Math.max(0, (int) ((orthoCachedTiledMapRenderer.cacheBounds.y - layerOffsetY2) / layerTileHeight2));
        int row2 = Math.min(layerHeight2, (int) ((((orthoCachedTiledMapRenderer.cacheBounds.y + orthoCachedTiledMapRenderer.cacheBounds.height) + layerTileHeight2) - layerOffsetY2) / layerTileHeight2));
        orthoCachedTiledMapRenderer.canCacheMoreN = row2 < layerHeight2;
        orthoCachedTiledMapRenderer.canCacheMoreE = col22 < layerWidth2;
        orthoCachedTiledMapRenderer.canCacheMoreW = col12 > 0;
        orthoCachedTiledMapRenderer.canCacheMoreS = row12 > 0;
        float[] vertices = orthoCachedTiledMapRenderer.vertices;
        int row = row2;
        while (row >= row12) {
            int col = col12;
            while (col < col22) {
                TiledMapTileLayer.Cell cell = layer.getCell(col, row);
                if (cell == null) {
                    color = color2;
                    layerWidth = layerWidth2;
                    layerHeight = layerHeight2;
                    layerTileWidth = layerTileWidth2;
                    layerTileHeight = layerTileHeight2;
                    layerOffsetX = layerOffsetX2;
                    layerOffsetY = layerOffsetY2;
                    col1 = col12;
                    col2 = col22;
                    row1 = row12;
                } else {
                    TiledMapTile tile = cell.getTile();
                    if (tile == null) {
                        color = color2;
                        layerWidth = layerWidth2;
                        layerHeight = layerHeight2;
                        layerTileWidth = layerTileWidth2;
                        layerTileHeight = layerTileHeight2;
                        layerOffsetX = layerOffsetX2;
                        layerOffsetY = layerOffsetY2;
                        col1 = col12;
                        col2 = col22;
                        row1 = row12;
                    } else {
                        layerWidth = layerWidth2;
                        orthoCachedTiledMapRenderer.count++;
                        boolean flipX = cell.getFlipHorizontally();
                        boolean flipY = cell.getFlipVertically();
                        layerHeight = layerHeight2;
                        int rotations = cell.getRotation();
                        TextureRegion region = tile.getTextureRegion();
                        col1 = col12;
                        Texture texture = region.getTexture();
                        col2 = col22;
                        layerTileWidth = layerTileWidth2;
                        float x1 = (col * layerTileWidth2) + (tile.getOffsetX() * orthoCachedTiledMapRenderer.unitScale) + layerOffsetX2;
                        layerTileHeight = layerTileHeight2;
                        float y1 = (row * layerTileHeight2) + (tile.getOffsetY() * orthoCachedTiledMapRenderer.unitScale) + layerOffsetY2;
                        layerOffsetX = layerOffsetX2;
                        float x2 = (region.getRegionWidth() * orthoCachedTiledMapRenderer.unitScale) + x1;
                        layerOffsetY = layerOffsetY2;
                        float y2 = (region.getRegionHeight() * orthoCachedTiledMapRenderer.unitScale) + y1;
                        float adjustX = 0.5f / texture.getWidth();
                        row1 = row12;
                        float adjustY = 0.5f / texture.getHeight();
                        float u1 = region.getU() + adjustX;
                        float v1 = region.getV2() - adjustY;
                        float u2 = region.getU2() - adjustX;
                        float v2 = region.getV() + adjustY;
                        vertices[0] = x1;
                        vertices[1] = y1;
                        vertices[2] = color2;
                        vertices[3] = u1;
                        vertices[4] = v1;
                        vertices[5] = x1;
                        vertices[6] = y2;
                        vertices[7] = color2;
                        vertices[8] = u1;
                        vertices[9] = v2;
                        vertices[10] = x2;
                        vertices[11] = y2;
                        vertices[12] = color2;
                        vertices[13] = u2;
                        vertices[14] = v2;
                        vertices[15] = x2;
                        vertices[16] = y1;
                        vertices[17] = color2;
                        vertices[18] = u2;
                        vertices[19] = v1;
                        if (flipX) {
                            float temp = vertices[3];
                            vertices[3] = vertices[13];
                            vertices[13] = temp;
                            float temp2 = vertices[8];
                            vertices[8] = vertices[18];
                            vertices[18] = temp2;
                        }
                        if (flipY) {
                            float temp3 = vertices[4];
                            vertices[4] = vertices[14];
                            vertices[14] = temp3;
                            float temp4 = vertices[9];
                            vertices[9] = vertices[19];
                            vertices[19] = temp4;
                        }
                        if (rotations != 0) {
                            if (rotations == 1) {
                                float tempU = vertices[4];
                                vertices[4] = vertices[9];
                                vertices[9] = vertices[14];
                                vertices[14] = vertices[19];
                                vertices[19] = tempU;
                                float tempU2 = vertices[3];
                                vertices[3] = vertices[8];
                                vertices[8] = vertices[13];
                                vertices[13] = vertices[18];
                                vertices[18] = tempU2;
                            } else if (rotations == 2) {
                                float tempU3 = vertices[3];
                                vertices[3] = vertices[13];
                                vertices[13] = tempU3;
                                float tempU4 = vertices[8];
                                float tempU5 = vertices[18];
                                vertices[8] = tempU5;
                                vertices[18] = tempU4;
                                float tempV = vertices[4];
                                vertices[4] = vertices[14];
                                vertices[14] = tempV;
                                float tempV2 = vertices[9];
                                vertices[9] = vertices[19];
                                vertices[19] = tempV2;
                            } else if (rotations == 3) {
                                float tempV3 = vertices[4];
                                vertices[4] = vertices[19];
                                vertices[19] = vertices[14];
                                vertices[14] = vertices[9];
                                vertices[9] = tempV3;
                                float tempU6 = vertices[3];
                                vertices[3] = vertices[18];
                                vertices[18] = vertices[13];
                                vertices[13] = vertices[8];
                                vertices[8] = tempU6;
                            }
                        }
                        color = color2;
                        orthoCachedTiledMapRenderer.spriteCache.add(texture, vertices, 0, 20);
                    }
                }
                col++;
                orthoCachedTiledMapRenderer = this;
                layerWidth2 = layerWidth;
                layerHeight2 = layerHeight;
                col12 = col1;
                col22 = col2;
                layerOffsetX2 = layerOffsetX;
                layerTileWidth2 = layerTileWidth;
                layerTileHeight2 = layerTileHeight;
                layerOffsetY2 = layerOffsetY;
                row12 = row1;
                color2 = color;
            }
            row--;
            orthoCachedTiledMapRenderer = this;
            color2 = color2;
        }
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderImageLayer(TiledMapImageLayer layer) {
        float color = Color.toFloatBits(1.0f, 1.0f, 1.0f, layer.getOpacity());
        float[] vertices = this.vertices;
        TextureRegion region = layer.getTextureRegion();
        if (region == null) {
            return;
        }
        float x = layer.getX();
        float y = layer.getY();
        float f = this.unitScale;
        float x1 = x * f;
        float y1 = f * y;
        float x2 = (region.getRegionWidth() * this.unitScale) + x1;
        float y2 = (region.getRegionHeight() * this.unitScale) + y1;
        float u1 = region.getU();
        float v1 = region.getV2();
        float u2 = region.getU2();
        float v2 = region.getV();
        vertices[0] = x1;
        vertices[1] = y1;
        vertices[2] = color;
        vertices[3] = u1;
        vertices[4] = v1;
        vertices[5] = x1;
        vertices[6] = y2;
        vertices[7] = color;
        vertices[8] = u1;
        vertices[9] = v2;
        vertices[10] = x2;
        vertices[11] = y2;
        vertices[12] = color;
        vertices[13] = u2;
        vertices[14] = v2;
        vertices[15] = x2;
        vertices[16] = y1;
        vertices[17] = color;
        vertices[18] = u2;
        vertices[19] = v1;
        this.spriteCache.add(region.getTexture(), vertices, 0, 20);
    }

    public void invalidateCache() {
        this.cached = false;
    }

    public boolean isCached() {
        return this.cached;
    }

    public void setOverCache(float overCache) {
        this.overCache = overCache;
    }

    public void setMaxTileSize(float maxPixelWidth, float maxPixelHeight) {
        this.maxTileWidth = maxPixelWidth;
        this.maxTileHeight = maxPixelHeight;
    }

    public void setBlending(boolean blending) {
        this.blending = blending;
    }

    public SpriteCache getSpriteCache() {
        return this.spriteCache;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.spriteCache.dispose();
    }
}