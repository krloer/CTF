package com.badlogic.gdx.graphics.g2d;

/* loaded from: classes.dex */
public class PolygonRegion {
    final TextureRegion region;
    final float[] textureCoords;
    final short[] triangles;
    final float[] vertices;

    public PolygonRegion(TextureRegion region, float[] vertices, short[] triangles) {
        this.region = region;
        this.vertices = vertices;
        this.triangles = triangles;
        float[] textureCoords = new float[vertices.length];
        this.textureCoords = textureCoords;
        float u = region.u;
        float v = region.v;
        float uvWidth = region.u2 - u;
        float uvHeight = region.v2 - v;
        int width = region.regionWidth;
        int height = region.regionHeight;
        int n = vertices.length;
        for (int i = 0; i < n; i += 2) {
            textureCoords[i] = ((vertices[i] / width) * uvWidth) + u;
            textureCoords[i + 1] = ((1.0f - (vertices[i + 1] / height)) * uvHeight) + v;
        }
    }

    public float[] getVertices() {
        return this.vertices;
    }

    public short[] getTriangles() {
        return this.triangles;
    }

    public float[] getTextureCoords() {
        return this.textureCoords;
    }

    public TextureRegion getRegion() {
        return this.region;
    }
}