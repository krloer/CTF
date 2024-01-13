package com.badlogic.gdx.maps.tiled.renderers;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.tiled.TiledMap;
import com.badlogic.gdx.maps.tiled.TiledMapTile;
import com.badlogic.gdx.maps.tiled.TiledMapTileLayer;

/* loaded from: classes.dex */
public class OrthogonalTiledMapRenderer extends BatchTiledMapRenderer {
    public OrthogonalTiledMapRenderer(TiledMap map) {
        super(map);
    }

    public OrthogonalTiledMapRenderer(TiledMap map, Batch batch) {
        super(map, batch);
    }

    public OrthogonalTiledMapRenderer(TiledMap map, float unitScale) {
        super(map, unitScale);
    }

    public OrthogonalTiledMapRenderer(TiledMap map, float unitScale, Batch batch) {
        super(map, unitScale, batch);
    }

    @Override // com.badlogic.gdx.maps.tiled.TiledMapRenderer
    public void renderTileLayer(TiledMapTileLayer layer) {
        float color;
        int layerHeight;
        float layerOffsetX;
        float layerOffsetY;
        int col1;
        int col2;
        OrthogonalTiledMapRenderer orthogonalTiledMapRenderer = this;
        Color batchColor = orthogonalTiledMapRenderer.batch.getColor();
        float color2 = Color.toFloatBits(batchColor.r, batchColor.g, batchColor.b, batchColor.a * layer.getOpacity());
        int layerWidth = layer.getWidth();
        int layerHeight2 = layer.getHeight();
        float layerTileWidth = layer.getTileWidth() * orthogonalTiledMapRenderer.unitScale;
        float layerTileHeight = layer.getTileHeight() * orthogonalTiledMapRenderer.unitScale;
        float layerOffsetX2 = layer.getRenderOffsetX() * orthogonalTiledMapRenderer.unitScale;
        float layerOffsetY2 = (-layer.getRenderOffsetY()) * orthogonalTiledMapRenderer.unitScale;
        int col12 = Math.max(0, (int) ((orthogonalTiledMapRenderer.viewBounds.x - layerOffsetX2) / layerTileWidth));
        int col22 = Math.min(layerWidth, (int) ((((orthogonalTiledMapRenderer.viewBounds.x + orthogonalTiledMapRenderer.viewBounds.width) + layerTileWidth) - layerOffsetX2) / layerTileWidth));
        int row1 = Math.max(0, (int) ((orthogonalTiledMapRenderer.viewBounds.y - layerOffsetY2) / layerTileHeight));
        int row2 = Math.min(layerHeight2, (int) ((((orthogonalTiledMapRenderer.viewBounds.y + orthogonalTiledMapRenderer.viewBounds.height) + layerTileHeight) - layerOffsetY2) / layerTileHeight));
        float y = (row2 * layerTileHeight) + layerOffsetY2;
        float xStart = (col12 * layerTileWidth) + layerOffsetX2;
        float[] vertices = orthogonalTiledMapRenderer.vertices;
        float y2 = y;
        int row = row2;
        while (row >= row1) {
            float x = xStart;
            Color batchColor2 = batchColor;
            int col = col12;
            while (col < col22) {
                int layerWidth2 = layerWidth;
                TiledMapTileLayer.Cell cell = layer.getCell(col, row);
                if (cell == null) {
                    x += layerTileWidth;
                    color = color2;
                    layerHeight = layerHeight2;
                    layerOffsetX = layerOffsetX2;
                    layerOffsetY = layerOffsetY2;
                    col1 = col12;
                    col2 = col22;
                } else {
                    TiledMapTile tile = cell.getTile();
                    if (tile == null) {
                        color = color2;
                        layerHeight = layerHeight2;
                        layerOffsetX = layerOffsetX2;
                        layerOffsetY = layerOffsetY2;
                        col1 = col12;
                        col2 = col22;
                    } else {
                        boolean flipX = cell.getFlipHorizontally();
                        boolean flipY = cell.getFlipVertically();
                        int rotations = cell.getRotation();
                        TextureRegion region = tile.getTextureRegion();
                        layerHeight = layerHeight2;
                        float x1 = x + (tile.getOffsetX() * orthogonalTiledMapRenderer.unitScale);
                        layerOffsetX = layerOffsetX2;
                        float y1 = y2 + (tile.getOffsetY() * orthogonalTiledMapRenderer.unitScale);
                        layerOffsetY = layerOffsetY2;
                        float x2 = x1 + (region.getRegionWidth() * orthogonalTiledMapRenderer.unitScale);
                        col1 = col12;
                        float y22 = (region.getRegionHeight() * orthogonalTiledMapRenderer.unitScale) + y1;
                        float u1 = region.getU();
                        float v1 = region.getV2();
                        float u2 = region.getU2();
                        float v2 = region.getV();
                        vertices[0] = x1;
                        col2 = col22;
                        vertices[1] = y1;
                        vertices[2] = color2;
                        vertices[3] = u1;
                        vertices[4] = v1;
                        vertices[5] = x1;
                        vertices[6] = y22;
                        vertices[7] = color2;
                        vertices[8] = u1;
                        vertices[9] = v2;
                        vertices[10] = x2;
                        vertices[11] = y22;
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
                        orthogonalTiledMapRenderer.batch.draw(region.getTexture(), vertices, 0, 20);
                    }
                    x += layerTileWidth;
                }
                col++;
                orthogonalTiledMapRenderer = this;
                layerWidth = layerWidth2;
                layerHeight2 = layerHeight;
                layerOffsetX2 = layerOffsetX;
                layerOffsetY2 = layerOffsetY;
                col12 = col1;
                col22 = col2;
                color2 = color;
            }
            y2 -= layerTileHeight;
            row--;
            orthogonalTiledMapRenderer = this;
            layerWidth = layerWidth;
            batchColor = batchColor2;
        }
    }
}