package com.badlogic.gdx.maps.tiled;

import com.badlogic.gdx.maps.MapLayer;
import java.lang.reflect.Array;

/* loaded from: classes.dex */
public class TiledMapTileLayer extends MapLayer {
    private Cell[][] cells;
    private int height;
    private int tileHeight;
    private int tileWidth;
    private int width;

    public int getWidth() {
        return this.width;
    }

    public int getHeight() {
        return this.height;
    }

    public int getTileWidth() {
        return this.tileWidth;
    }

    public int getTileHeight() {
        return this.tileHeight;
    }

    public TiledMapTileLayer(int width, int height, int tileWidth, int tileHeight) {
        this.width = width;
        this.height = height;
        this.tileWidth = tileWidth;
        this.tileHeight = tileHeight;
        this.cells = (Cell[][]) Array.newInstance(Cell.class, width, height);
    }

    public Cell getCell(int x, int y) {
        if (x < 0 || x >= this.width || y < 0 || y >= this.height) {
            return null;
        }
        return this.cells[x][y];
    }

    public void setCell(int x, int y, Cell cell) {
        if (x < 0 || x >= this.width || y < 0 || y >= this.height) {
            return;
        }
        this.cells[x][y] = cell;
    }

    /* loaded from: classes.dex */
    public static class Cell {
        public static final int ROTATE_0 = 0;
        public static final int ROTATE_180 = 2;
        public static final int ROTATE_270 = 3;
        public static final int ROTATE_90 = 1;
        private boolean flipHorizontally;
        private boolean flipVertically;
        private int rotation;
        private TiledMapTile tile;

        public TiledMapTile getTile() {
            return this.tile;
        }

        public Cell setTile(TiledMapTile tile) {
            this.tile = tile;
            return this;
        }

        public boolean getFlipHorizontally() {
            return this.flipHorizontally;
        }

        public Cell setFlipHorizontally(boolean flipHorizontally) {
            this.flipHorizontally = flipHorizontally;
            return this;
        }

        public boolean getFlipVertically() {
            return this.flipVertically;
        }

        public Cell setFlipVertically(boolean flipVertically) {
            this.flipVertically = flipVertically;
            return this;
        }

        public int getRotation() {
            return this.rotation;
        }

        public Cell setRotation(int rotation) {
            this.rotation = rotation;
            return this;
        }
    }
}