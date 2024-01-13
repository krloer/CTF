package com.badlogic.gdx.maps.tiled.renderers;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.tiled.TiledMap;
import com.badlogic.gdx.maps.tiled.TiledMapTile;
import com.badlogic.gdx.maps.tiled.TiledMapTileLayer;

/* loaded from: classes.dex */
public class IsometricStaggeredTiledMapRenderer extends BatchTiledMapRenderer {
    public IsometricStaggeredTiledMapRenderer(TiledMap map) {
        super(map);
    }

    public IsometricStaggeredTiledMapRenderer(TiledMap map, Batch batch) {
        super(map, batch);
    }

    public IsometricStaggeredTiledMapRenderer(TiledMap map, float unitScale) {
        super(map, unitScale);
    }

    public IsometricStaggeredTiledMapRenderer(TiledMap map, float unitScale, Batch batch) {
        super(map, unitScale, batch);
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderTileLayer(TiledMapTileLayer layer) {
        float offsetX;
        float color;
        float layerOffsetX;
        float layerOffsetY;
        float layerTileWidth;
        float layerTileHeight;
        float layerTileHeight50;
        float layerTileWidth50;
        IsometricStaggeredTiledMapRenderer isometricStaggeredTiledMapRenderer = this;
        Color batchColor = isometricStaggeredTiledMapRenderer.batch.getColor();
        float color2 = Color.toFloatBits(batchColor.r, batchColor.g, batchColor.b, batchColor.a * layer.getOpacity());
        int layerWidth = layer.getWidth();
        int layerHeight = layer.getHeight();
        float layerOffsetX2 = layer.getRenderOffsetX() * isometricStaggeredTiledMapRenderer.unitScale;
        float layerOffsetY2 = (-layer.getRenderOffsetY()) * isometricStaggeredTiledMapRenderer.unitScale;
        float layerTileWidth2 = layer.getTileWidth() * isometricStaggeredTiledMapRenderer.unitScale;
        float layerTileHeight2 = layer.getTileHeight() * isometricStaggeredTiledMapRenderer.unitScale;
        float layerTileWidth502 = layerTileWidth2 * 0.5f;
        float layerTileHeight502 = 0.5f * layerTileHeight2;
        int minX = Math.max(0, (int) (((isometricStaggeredTiledMapRenderer.viewBounds.x - layerTileWidth502) - layerOffsetX2) / layerTileWidth2));
        int maxX = Math.min(layerWidth, (int) (((((isometricStaggeredTiledMapRenderer.viewBounds.x + isometricStaggeredTiledMapRenderer.viewBounds.width) + layerTileWidth2) + layerTileWidth502) - layerOffsetX2) / layerTileWidth2));
        int minY = Math.max(0, (int) (((isometricStaggeredTiledMapRenderer.viewBounds.y - layerTileHeight2) - layerOffsetY2) / layerTileHeight2));
        int maxY = Math.min(layerHeight, (int) ((((isometricStaggeredTiledMapRenderer.viewBounds.y + isometricStaggeredTiledMapRenderer.viewBounds.height) + layerTileHeight2) - layerOffsetY2) / layerTileHeight502));
        int y = maxY - 1;
        while (y >= minY) {
            Color batchColor2 = batchColor;
            int layerWidth2 = layerWidth;
            float offsetX2 = y % 2 == 1 ? layerTileWidth502 : 0.0f;
            int x = maxX - 1;
            while (x >= minX) {
                int layerHeight2 = layerHeight;
                TiledMapTileLayer.Cell cell = layer.getCell(x, y);
                if (cell == null) {
                    offsetX = offsetX2;
                    color = color2;
                    layerOffsetX = layerOffsetX2;
                    layerOffsetY = layerOffsetY2;
                    layerTileWidth = layerTileWidth2;
                    layerTileHeight = layerTileHeight2;
                    layerTileHeight50 = layerTileHeight502;
                    layerTileWidth50 = layerTileWidth502;
                } else {
                    TiledMapTile tile = cell.getTile();
                    if (tile == null) {
                        offsetX = offsetX2;
                        color = color2;
                        layerOffsetX = layerOffsetX2;
                        layerOffsetY = layerOffsetY2;
                        layerTileWidth = layerTileWidth2;
                        layerTileHeight = layerTileHeight2;
                        layerTileHeight50 = layerTileHeight502;
                        layerTileWidth50 = layerTileWidth502;
                    } else {
                        boolean flipX = cell.getFlipHorizontally();
                        boolean flipY = cell.getFlipVertically();
                        int rotations = cell.getRotation();
                        TextureRegion region = tile.getTextureRegion();
                        layerTileHeight = layerTileHeight2;
                        float f = (x * layerTileWidth2) - offsetX2;
                        float offsetX3 = tile.getOffsetX();
                        offsetX = offsetX2;
                        float offsetX4 = isometricStaggeredTiledMapRenderer.unitScale;
                        float x1 = f + (offsetX3 * offsetX4) + layerOffsetX2;
                        layerOffsetX = layerOffsetX2;
                        float y1 = (y * layerTileHeight502) + (tile.getOffsetY() * isometricStaggeredTiledMapRenderer.unitScale) + layerOffsetY2;
                        layerOffsetY = layerOffsetY2;
                        float x2 = (region.getRegionWidth() * isometricStaggeredTiledMapRenderer.unitScale) + x1;
                        layerTileWidth = layerTileWidth2;
                        float y2 = (region.getRegionHeight() * isometricStaggeredTiledMapRenderer.unitScale) + y1;
                        float u1 = region.getU();
                        float v1 = region.getV2();
                        float u2 = region.getU2();
                        float v2 = region.getV();
                        layerTileHeight50 = layerTileHeight502;
                        isometricStaggeredTiledMapRenderer.vertices[0] = x1;
                        isometricStaggeredTiledMapRenderer.vertices[1] = y1;
                        layerTileWidth50 = layerTileWidth502;
                        isometricStaggeredTiledMapRenderer.vertices[2] = color2;
                        isometricStaggeredTiledMapRenderer.vertices[3] = u1;
                        isometricStaggeredTiledMapRenderer.vertices[4] = v1;
                        isometricStaggeredTiledMapRenderer.vertices[5] = x1;
                        isometricStaggeredTiledMapRenderer.vertices[6] = y2;
                        isometricStaggeredTiledMapRenderer.vertices[7] = color2;
                        isometricStaggeredTiledMapRenderer.vertices[8] = u1;
                        isometricStaggeredTiledMapRenderer.vertices[9] = v2;
                        isometricStaggeredTiledMapRenderer.vertices[10] = x2;
                        isometricStaggeredTiledMapRenderer.vertices[11] = y2;
                        isometricStaggeredTiledMapRenderer.vertices[12] = color2;
                        isometricStaggeredTiledMapRenderer.vertices[13] = u2;
                        isometricStaggeredTiledMapRenderer.vertices[14] = v2;
                        isometricStaggeredTiledMapRenderer.vertices[15] = x2;
                        isometricStaggeredTiledMapRenderer.vertices[16] = y1;
                        isometricStaggeredTiledMapRenderer.vertices[17] = color2;
                        isometricStaggeredTiledMapRenderer.vertices[18] = u2;
                        isometricStaggeredTiledMapRenderer.vertices[19] = v1;
                        if (flipX) {
                            float temp = isometricStaggeredTiledMapRenderer.vertices[3];
                            isometricStaggeredTiledMapRenderer.vertices[3] = isometricStaggeredTiledMapRenderer.vertices[13];
                            isometricStaggeredTiledMapRenderer.vertices[13] = temp;
                            float temp2 = isometricStaggeredTiledMapRenderer.vertices[8];
                            isometricStaggeredTiledMapRenderer.vertices[8] = isometricStaggeredTiledMapRenderer.vertices[18];
                            isometricStaggeredTiledMapRenderer.vertices[18] = temp2;
                        }
                        if (flipY) {
                            float temp3 = isometricStaggeredTiledMapRenderer.vertices[4];
                            isometricStaggeredTiledMapRenderer.vertices[4] = isometricStaggeredTiledMapRenderer.vertices[14];
                            isometricStaggeredTiledMapRenderer.vertices[14] = temp3;
                            float temp4 = isometricStaggeredTiledMapRenderer.vertices[9];
                            isometricStaggeredTiledMapRenderer.vertices[9] = isometricStaggeredTiledMapRenderer.vertices[19];
                            isometricStaggeredTiledMapRenderer.vertices[19] = temp4;
                        }
                        if (rotations == 0) {
                            color = color2;
                        } else if (rotations == 1) {
                            color = color2;
                            float tempV = isometricStaggeredTiledMapRenderer.vertices[4];
                            isometricStaggeredTiledMapRenderer.vertices[4] = isometricStaggeredTiledMapRenderer.vertices[9];
                            isometricStaggeredTiledMapRenderer.vertices[9] = isometricStaggeredTiledMapRenderer.vertices[14];
                            isometricStaggeredTiledMapRenderer.vertices[14] = isometricStaggeredTiledMapRenderer.vertices[19];
                            isometricStaggeredTiledMapRenderer.vertices[19] = tempV;
                            float tempU = isometricStaggeredTiledMapRenderer.vertices[3];
                            isometricStaggeredTiledMapRenderer.vertices[3] = isometricStaggeredTiledMapRenderer.vertices[8];
                            isometricStaggeredTiledMapRenderer.vertices[8] = isometricStaggeredTiledMapRenderer.vertices[13];
                            isometricStaggeredTiledMapRenderer.vertices[13] = isometricStaggeredTiledMapRenderer.vertices[18];
                            isometricStaggeredTiledMapRenderer.vertices[18] = tempU;
                        } else if (rotations == 2) {
                            color = color2;
                            float tempU2 = isometricStaggeredTiledMapRenderer.vertices[3];
                            isometricStaggeredTiledMapRenderer.vertices[3] = isometricStaggeredTiledMapRenderer.vertices[13];
                            isometricStaggeredTiledMapRenderer.vertices[13] = tempU2;
                            float tempU3 = isometricStaggeredTiledMapRenderer.vertices[8];
                            isometricStaggeredTiledMapRenderer.vertices[8] = isometricStaggeredTiledMapRenderer.vertices[18];
                            isometricStaggeredTiledMapRenderer.vertices[18] = tempU3;
                            float tempV2 = isometricStaggeredTiledMapRenderer.vertices[4];
                            isometricStaggeredTiledMapRenderer.vertices[4] = isometricStaggeredTiledMapRenderer.vertices[14];
                            isometricStaggeredTiledMapRenderer.vertices[14] = tempV2;
                            float tempV3 = isometricStaggeredTiledMapRenderer.vertices[9];
                            isometricStaggeredTiledMapRenderer.vertices[9] = isometricStaggeredTiledMapRenderer.vertices[19];
                            isometricStaggeredTiledMapRenderer.vertices[19] = tempV3;
                        } else if (rotations != 3) {
                            color = color2;
                        } else {
                            float tempV4 = isometricStaggeredTiledMapRenderer.vertices[4];
                            isometricStaggeredTiledMapRenderer.vertices[4] = isometricStaggeredTiledMapRenderer.vertices[19];
                            isometricStaggeredTiledMapRenderer.vertices[19] = isometricStaggeredTiledMapRenderer.vertices[14];
                            isometricStaggeredTiledMapRenderer.vertices[14] = isometricStaggeredTiledMapRenderer.vertices[9];
                            isometricStaggeredTiledMapRenderer.vertices[9] = tempV4;
                            float tempU4 = isometricStaggeredTiledMapRenderer.vertices[3];
                            color = color2;
                            isometricStaggeredTiledMapRenderer.vertices[3] = isometricStaggeredTiledMapRenderer.vertices[18];
                            isometricStaggeredTiledMapRenderer.vertices[18] = isometricStaggeredTiledMapRenderer.vertices[13];
                            isometricStaggeredTiledMapRenderer.vertices[13] = isometricStaggeredTiledMapRenderer.vertices[8];
                            isometricStaggeredTiledMapRenderer.vertices[8] = tempU4;
                        }
                        isometricStaggeredTiledMapRenderer.batch.draw(region.getTexture(), isometricStaggeredTiledMapRenderer.vertices, 0, 20);
                    }
                }
                x--;
                isometricStaggeredTiledMapRenderer = this;
                layerHeight = layerHeight2;
                layerTileHeight2 = layerTileHeight;
                layerOffsetY2 = layerOffsetY;
                offsetX2 = offsetX;
                layerOffsetX2 = layerOffsetX;
                layerTileWidth2 = layerTileWidth;
                layerTileHeight502 = layerTileHeight50;
                layerTileWidth502 = layerTileWidth50;
                color2 = color;
            }
            y--;
            isometricStaggeredTiledMapRenderer = this;
            batchColor = batchColor2;
            layerWidth = layerWidth2;
        }
    }
}