package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.math.EarClippingTriangulator;
import com.badlogic.gdx.math.Intersector;
import com.badlogic.gdx.math.Polygon;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ShortArray;

/* loaded from: classes.dex */
public class RepeatablePolygonSprite {
    private int cols;
    private float density;
    private float gridHeight;
    private float gridWidth;
    private TextureRegion region;
    private int rows;
    private boolean dirty = true;
    private Array<float[]> parts = new Array<>();
    private Array<float[]> vertices = new Array<>();
    private Array<short[]> indices = new Array<>();
    public float x = 0.0f;
    public float y = 0.0f;
    private Color color = Color.WHITE;
    private Vector2 offset = new Vector2();

    public void setPolygon(TextureRegion region, float[] vertices) {
        setPolygon(region, vertices, -1.0f);
    }

    public void setPolygon(TextureRegion region, float[] vertices, float density) {
        this.region = region;
        float[] vertices2 = offset(vertices);
        Polygon polygon = new Polygon(vertices2);
        Polygon tmpPoly = new Polygon();
        Polygon intersectionPoly = new Polygon();
        EarClippingTriangulator triangulator = new EarClippingTriangulator();
        Rectangle boundRect = polygon.getBoundingRectangle();
        float density2 = density == -1.0f ? boundRect.getWidth() / region.getRegionWidth() : density;
        float regionAspectRatio = region.getRegionHeight() / region.getRegionWidth();
        this.cols = (int) Math.ceil(density2);
        this.gridWidth = boundRect.getWidth() / density2;
        this.gridHeight = this.gridWidth * regionAspectRatio;
        this.rows = (int) Math.ceil(boundRect.getHeight() / this.gridHeight);
        for (int col = 0; col < this.cols; col++) {
            int row = 0;
            while (row < this.rows) {
                float[] verts = new float[8];
                int idx = 0 + 1;
                float f = this.gridWidth;
                verts[0] = col * f;
                int idx2 = idx + 1;
                float[] vertices3 = vertices2;
                float f2 = this.gridHeight;
                verts[idx] = row * f2;
                int idx3 = idx2 + 1;
                verts[idx2] = col * f;
                int idx4 = idx3 + 1;
                verts[idx3] = (row + 1) * f2;
                int idx5 = idx4 + 1;
                verts[idx4] = (col + 1) * f;
                int idx6 = idx5 + 1;
                verts[idx5] = (row + 1) * f2;
                verts[idx6] = (col + 1) * f;
                verts[idx6 + 1] = row * f2;
                tmpPoly.setVertices(verts);
                Intersector.intersectPolygons(polygon, tmpPoly, intersectionPoly);
                float[] verts2 = intersectionPoly.getVertices();
                if (verts2.length > 0) {
                    this.parts.add(snapToGrid(verts2));
                    ShortArray arr = triangulator.computeTriangles(verts2);
                    this.indices.add(arr.toArray());
                } else {
                    this.parts.add(null);
                }
                row++;
                vertices2 = vertices3;
            }
        }
        buildVertices();
    }

    private float[] snapToGrid(float[] vertices) {
        for (int i = 0; i < vertices.length; i += 2) {
            float numX = (vertices[i] / this.gridWidth) % 1.0f;
            float numY = (vertices[i + 1] / this.gridHeight) % 1.0f;
            if (numX > 0.99f || numX < 0.01f) {
                float f = this.gridWidth;
                vertices[i] = f * Math.round(vertices[i] / f);
            }
            if (numY > 0.99f || numY < 0.01f) {
                float f2 = this.gridHeight;
                vertices[i + 1] = f2 * Math.round(vertices[i + 1] / f2);
            }
        }
        return vertices;
    }

    private float[] offset(float[] vertices) {
        this.offset.set(vertices[0], vertices[1]);
        for (int i = 0; i < vertices.length - 1; i += 2) {
            if (this.offset.x > vertices[i]) {
                this.offset.x = vertices[i];
            }
            if (this.offset.y > vertices[i + 1]) {
                this.offset.y = vertices[i + 1];
            }
        }
        for (int i2 = 0; i2 < vertices.length; i2 += 2) {
            vertices[i2] = vertices[i2] - this.offset.x;
            int i3 = i2 + 1;
            vertices[i3] = vertices[i3] - this.offset.y;
        }
        return vertices;
    }

    private void buildVertices() {
        this.vertices.clear();
        for (int i = 0; i < this.parts.size; i++) {
            float[] verts = this.parts.get(i);
            if (verts != null) {
                float[] fullVerts = new float[(verts.length * 5) / 2];
                int idx = 0;
                int i2 = this.rows;
                int col = i / i2;
                int row = i % i2;
                int j = 0;
                while (j < verts.length) {
                    int idx2 = idx + 1;
                    fullVerts[idx] = verts[j] + this.offset.x + this.x;
                    int idx3 = idx2 + 1;
                    fullVerts[idx2] = verts[j + 1] + this.offset.y + this.y;
                    int idx4 = idx3 + 1;
                    fullVerts[idx3] = this.color.toFloatBits();
                    float f = verts[j];
                    float f2 = this.gridWidth;
                    float u = (f % f2) / f2;
                    float f3 = verts[j + 1];
                    float f4 = this.gridHeight;
                    float v = (f3 % f4) / f4;
                    if (verts[j] == col * f2) {
                        u = 0.0f;
                    }
                    if (verts[j] == (col + 1) * this.gridWidth) {
                        u = 1.0f;
                    }
                    if (verts[j + 1] == row * this.gridHeight) {
                        v = 0.0f;
                    }
                    if (verts[j + 1] == (row + 1) * this.gridHeight) {
                        v = 1.0f;
                    }
                    float u2 = this.region.getU() + ((this.region.getU2() - this.region.getU()) * u);
                    float v2 = this.region.getV() + ((this.region.getV2() - this.region.getV()) * v);
                    int idx5 = idx4 + 1;
                    fullVerts[idx4] = u2;
                    fullVerts[idx5] = v2;
                    j += 2;
                    idx = idx5 + 1;
                }
                this.vertices.add(fullVerts);
            }
        }
        this.dirty = false;
    }

    public void draw(PolygonSpriteBatch batch) {
        if (this.dirty) {
            buildVertices();
        }
        for (int i = 0; i < this.vertices.size; i++) {
            batch.draw(this.region.getTexture(), this.vertices.get(i), 0, this.vertices.get(i).length, this.indices.get(i), 0, this.indices.get(i).length);
        }
    }

    public void setColor(Color color) {
        this.color = color;
        this.dirty = true;
    }

    public void setPosition(float x, float y) {
        this.x = x;
        this.y = y;
        this.dirty = true;
    }
}