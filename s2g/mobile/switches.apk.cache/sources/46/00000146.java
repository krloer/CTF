package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.IntArray;
import java.nio.FloatBuffer;

/* loaded from: classes.dex */
public class SpriteCache implements Disposable {
    private static final float[] tempVertices = new float[30];
    private Array<Cache> caches;
    private final Color color;
    private float colorPacked;
    private final Matrix4 combinedMatrix;
    private final IntArray counts;
    private Cache currentCache;
    private ShaderProgram customShader;
    private boolean drawing;
    private final Mesh mesh;
    private final Matrix4 projectionMatrix;
    public int renderCalls;
    private final ShaderProgram shader;
    private final Array<Texture> textures;
    public int totalRenderCalls;
    private final Matrix4 transformMatrix;

    public SpriteCache() {
        this(1000, false);
    }

    public SpriteCache(int size, boolean useIndices) {
        this(size, createDefaultShader(), useIndices);
    }

    public SpriteCache(int size, ShaderProgram shader, boolean useIndices) {
        this.transformMatrix = new Matrix4();
        this.projectionMatrix = new Matrix4();
        this.caches = new Array<>();
        this.combinedMatrix = new Matrix4();
        this.textures = new Array<>(8);
        this.counts = new IntArray(8);
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.colorPacked = Color.WHITE_FLOAT_BITS;
        this.customShader = null;
        this.renderCalls = 0;
        this.totalRenderCalls = 0;
        this.shader = shader;
        if (useIndices && size > 8191) {
            throw new IllegalArgumentException("Can't have more than 8191 sprites per batch: " + size);
        }
        this.mesh = new Mesh(true, (useIndices ? 4 : 6) * size, useIndices ? size * 6 : 0, new VertexAttribute(1, 2, ShaderProgram.POSITION_ATTRIBUTE), new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE), new VertexAttribute(16, 2, "a_texCoord0"));
        this.mesh.setAutoBind(false);
        if (useIndices) {
            int length = size * 6;
            short[] indices = new short[length];
            short j = 0;
            int i = 0;
            while (i < length) {
                indices[i + 0] = j;
                indices[i + 1] = (short) (j + 1);
                indices[i + 2] = (short) (j + 2);
                indices[i + 3] = (short) (j + 2);
                indices[i + 4] = (short) (j + 3);
                indices[i + 5] = j;
                i += 6;
                j = (short) (j + 4);
            }
            this.mesh.setIndices(indices);
        }
        this.projectionMatrix.setToOrtho2D(0.0f, 0.0f, Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
    }

    public void setColor(Color tint) {
        this.color.set(tint);
        this.colorPacked = tint.toFloatBits();
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        this.colorPacked = this.color.toFloatBits();
    }

    public Color getColor() {
        return this.color;
    }

    public void setPackedColor(float packedColor) {
        Color.abgr8888ToColor(this.color, packedColor);
        this.colorPacked = packedColor;
    }

    public float getPackedColor() {
        return this.colorPacked;
    }

    public void beginCache() {
        if (this.drawing) {
            throw new IllegalStateException("end must be called before beginCache");
        }
        if (this.currentCache != null) {
            throw new IllegalStateException("endCache must be called before begin.");
        }
        if (this.mesh.getNumIndices() > 0) {
        }
        this.currentCache = new Cache(this.caches.size, this.mesh.getVerticesBuffer().limit());
        this.caches.add(this.currentCache);
        this.mesh.getVerticesBuffer().compact();
    }

    public void beginCache(int cacheID) {
        if (this.drawing) {
            throw new IllegalStateException("end must be called before beginCache");
        }
        if (this.currentCache != null) {
            throw new IllegalStateException("endCache must be called before begin.");
        }
        if (cacheID == this.caches.size - 1) {
            Cache oldCache = this.caches.removeIndex(cacheID);
            this.mesh.getVerticesBuffer().limit(oldCache.offset);
            beginCache();
            return;
        }
        this.currentCache = this.caches.get(cacheID);
        this.mesh.getVerticesBuffer().position(this.currentCache.offset);
    }

    public int endCache() {
        if (this.currentCache == null) {
            throw new IllegalStateException("beginCache must be called before endCache.");
        }
        Cache cache = this.currentCache;
        int cacheCount = this.mesh.getVerticesBuffer().position() - cache.offset;
        if (cache.textures == null) {
            cache.maxCount = cacheCount;
            cache.textureCount = this.textures.size;
            cache.textures = (Texture[]) this.textures.toArray(Texture.class);
            cache.counts = new int[cache.textureCount];
            int n = this.counts.size;
            for (int i = 0; i < n; i++) {
                cache.counts[i] = this.counts.get(i);
            }
            this.mesh.getVerticesBuffer().flip();
        } else if (cacheCount > cache.maxCount) {
            throw new GdxRuntimeException("If a cache is not the last created, it cannot be redefined with more entries than when it was first created: " + cacheCount + " (" + cache.maxCount + " max)");
        } else {
            cache.textureCount = this.textures.size;
            if (cache.textures.length < cache.textureCount) {
                cache.textures = new Texture[cache.textureCount];
            }
            int n2 = cache.textureCount;
            for (int i2 = 0; i2 < n2; i2++) {
                cache.textures[i2] = this.textures.get(i2);
            }
            if (cache.counts.length < cache.textureCount) {
                cache.counts = new int[cache.textureCount];
            }
            int n3 = cache.textureCount;
            for (int i3 = 0; i3 < n3; i3++) {
                cache.counts[i3] = this.counts.get(i3);
            }
            FloatBuffer vertices = this.mesh.getVerticesBuffer();
            vertices.position(0);
            Array<Cache> array = this.caches;
            Cache lastCache = array.get(array.size - 1);
            vertices.limit(lastCache.offset + lastCache.maxCount);
        }
        this.currentCache = null;
        this.textures.clear();
        this.counts.clear();
        return cache.id;
    }

    public void clear() {
        this.caches.clear();
        this.mesh.getVerticesBuffer().clear().flip();
    }

    public void add(Texture texture, float[] vertices, int offset, int length) {
        if (this.currentCache == null) {
            throw new IllegalStateException("beginCache must be called before add.");
        }
        int verticesPerImage = this.mesh.getNumIndices() > 0 ? 4 : 6;
        int count = (length / (verticesPerImage * 5)) * 6;
        int lastIndex = this.textures.size - 1;
        if (lastIndex < 0 || this.textures.get(lastIndex) != texture) {
            this.textures.add(texture);
            this.counts.add(count);
        } else {
            this.counts.incr(lastIndex, count);
        }
        this.mesh.getVerticesBuffer().put(vertices, offset, length);
    }

    public void add(Texture texture, float x, float y) {
        float fx2 = texture.getWidth() + x;
        float fy2 = texture.getHeight() + y;
        float[] fArr = tempVertices;
        fArr[0] = x;
        fArr[1] = y;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = 0.0f;
        fArr[4] = 1.0f;
        fArr[5] = x;
        fArr[6] = fy2;
        fArr[7] = f;
        fArr[8] = 0.0f;
        fArr[9] = 0.0f;
        fArr[10] = fx2;
        fArr[11] = fy2;
        fArr[12] = f;
        fArr[13] = 1.0f;
        fArr[14] = 0.0f;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = fx2;
            fArr2[16] = y;
            fArr2[17] = this.colorPacked;
            fArr2[18] = 1.0f;
            fArr2[19] = 1.0f;
            add(texture, fArr2, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = fx2;
        fArr3[16] = fy2;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = 1.0f;
        fArr3[19] = 0.0f;
        fArr3[20] = fx2;
        fArr3[21] = y;
        fArr3[22] = f2;
        fArr3[23] = 1.0f;
        fArr3[24] = 1.0f;
        fArr3[25] = x;
        fArr3[26] = y;
        fArr3[27] = f2;
        fArr3[28] = 0.0f;
        fArr3[29] = 1.0f;
        add(texture, fArr3, 0, 30);
    }

    public void add(Texture texture, float x, float y, int srcWidth, int srcHeight, float u, float v, float u2, float v2, float color) {
        float fx2 = x + srcWidth;
        float fy2 = y + srcHeight;
        float[] fArr = tempVertices;
        fArr[0] = x;
        fArr[1] = y;
        fArr[2] = color;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x;
        fArr[6] = fy2;
        fArr[7] = color;
        fArr[8] = u;
        fArr[9] = v2;
        fArr[10] = fx2;
        fArr[11] = fy2;
        fArr[12] = color;
        fArr[13] = u2;
        fArr[14] = v2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = fx2;
            fArr2[16] = y;
            fArr2[17] = color;
            fArr2[18] = u2;
            fArr2[19] = v;
            add(texture, fArr2, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = fx2;
        fArr3[16] = fy2;
        fArr3[17] = color;
        fArr3[18] = u2;
        fArr3[19] = v2;
        fArr3[20] = fx2;
        fArr3[21] = y;
        fArr3[22] = color;
        fArr3[23] = u2;
        fArr3[24] = v;
        fArr3[25] = x;
        fArr3[26] = y;
        fArr3[27] = color;
        fArr3[28] = u;
        fArr3[29] = v;
        add(texture, fArr3, 0, 30);
    }

    public void add(Texture texture, float x, float y, int srcX, int srcY, int srcWidth, int srcHeight) {
        float invTexWidth = 1.0f / texture.getWidth();
        float invTexHeight = 1.0f / texture.getHeight();
        float u = srcX * invTexWidth;
        float v = (srcY + srcHeight) * invTexHeight;
        float u2 = (srcX + srcWidth) * invTexWidth;
        float v2 = srcY * invTexHeight;
        float fx2 = x + srcWidth;
        float fy2 = y + srcHeight;
        float[] fArr = tempVertices;
        fArr[0] = x;
        fArr[1] = y;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x;
        fArr[6] = fy2;
        fArr[7] = f;
        fArr[8] = u;
        fArr[9] = v2;
        fArr[10] = fx2;
        fArr[11] = fy2;
        fArr[12] = f;
        fArr[13] = u2;
        fArr[14] = v2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = fx2;
            fArr2[16] = y;
            fArr2[17] = this.colorPacked;
            fArr2[18] = u2;
            fArr2[19] = v;
            add(texture, fArr2, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = fx2;
        fArr3[16] = fy2;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = u2;
        fArr3[19] = v2;
        fArr3[20] = fx2;
        fArr3[21] = y;
        fArr3[22] = f2;
        fArr3[23] = u2;
        fArr3[24] = v;
        fArr3[25] = x;
        fArr3[26] = y;
        fArr3[27] = f2;
        fArr3[28] = u;
        fArr3[29] = v;
        add(texture, fArr3, 0, 30);
    }

    public void add(Texture texture, float x, float y, float width, float height, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        float invTexWidth = 1.0f / texture.getWidth();
        float invTexHeight = 1.0f / texture.getHeight();
        float u = srcX * invTexWidth;
        float v = (srcY + srcHeight) * invTexHeight;
        float u2 = (srcX + srcWidth) * invTexWidth;
        float v2 = srcY * invTexHeight;
        float fx2 = x + width;
        float fy2 = y + height;
        if (flipX) {
            u = u2;
            u2 = u;
        }
        if (flipY) {
            v = v2;
            v2 = v;
        }
        float[] fArr = tempVertices;
        fArr[0] = x;
        fArr[1] = y;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x;
        fArr[6] = fy2;
        fArr[7] = f;
        fArr[8] = u;
        fArr[9] = v2;
        fArr[10] = fx2;
        fArr[11] = fy2;
        fArr[12] = f;
        fArr[13] = u2;
        fArr[14] = v2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = fx2;
            fArr2[16] = y;
            fArr2[17] = this.colorPacked;
            fArr2[18] = u2;
            fArr2[19] = v;
            add(texture, fArr2, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = fx2;
        fArr3[16] = fy2;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = u2;
        fArr3[19] = v2;
        fArr3[20] = fx2;
        fArr3[21] = y;
        fArr3[22] = f2;
        fArr3[23] = u2;
        fArr3[24] = v;
        fArr3[25] = x;
        fArr3[26] = y;
        fArr3[27] = f2;
        fArr3[28] = u;
        fArr3[29] = v;
        add(texture, fArr3, 0, 30);
    }

    public void add(Texture texture, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        float worldOriginX = x + originX;
        float worldOriginY = y + originY;
        float fx = -originX;
        float fy = -originY;
        float fx2 = width - originX;
        float fy2 = height - originY;
        if (scaleX != 1.0f || scaleY != 1.0f) {
            fx *= scaleX;
            fy *= scaleY;
            fx2 *= scaleX;
            fy2 *= scaleY;
        }
        float p1x = fx;
        float p1y = fy;
        float p2x = fx;
        float p2y = fy2;
        float p3x = fx2;
        float p3y = fy2;
        float p4x = fx2;
        float p4y = fy;
        if (rotation != 0.0f) {
            float cos2 = MathUtils.cosDeg(rotation);
            float sin = MathUtils.sinDeg(rotation);
            x1 = (cos2 * p1x) - (sin * p1y);
            y1 = (sin * p1x) + (cos2 * p1y);
            x2 = (cos2 * p2x) - (sin * p2y);
            y2 = (sin * p2x) + (cos2 * p2y);
            x3 = (cos2 * p3x) - (sin * p3y);
            y3 = (sin * p3x) + (cos2 * p3y);
            x4 = x1 + (x3 - x2);
            cos = y3 - (y2 - y1);
        } else {
            x1 = p1x;
            y1 = p1y;
            x2 = p2x;
            y2 = p2y;
            x3 = p3x;
            y3 = p3y;
            x4 = p4x;
            cos = p4y;
        }
        float x12 = x1 + worldOriginX;
        float y12 = y1 + worldOriginY;
        float x22 = x2 + worldOriginX;
        float y22 = y2 + worldOriginY;
        float x32 = x3 + worldOriginX;
        float y32 = y3 + worldOriginY;
        float x42 = x4 + worldOriginX;
        float y4 = cos + worldOriginY;
        float invTexWidth = 1.0f / texture.getWidth();
        float invTexHeight = 1.0f / texture.getHeight();
        float u = srcX * invTexWidth;
        float v = (srcY + srcHeight) * invTexHeight;
        float u2 = (srcX + srcWidth) * invTexWidth;
        float v2 = srcY * invTexHeight;
        if (flipX) {
            u = u2;
            u2 = u;
        }
        if (flipY) {
            v = v2;
            v2 = v;
        }
        float[] fArr = tempVertices;
        fArr[0] = x12;
        fArr[1] = y12;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x22;
        fArr[6] = y22;
        fArr[7] = f;
        fArr[8] = u;
        fArr[9] = v2;
        fArr[10] = x32;
        fArr[11] = y32;
        fArr[12] = f;
        fArr[13] = u2;
        fArr[14] = v2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = x42;
            fArr2[16] = y4;
            fArr2[17] = this.colorPacked;
            fArr2[18] = u2;
            fArr2[19] = v;
            add(texture, fArr2, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = x32;
        fArr3[16] = y32;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = u2;
        fArr3[19] = v2;
        fArr3[20] = x42;
        fArr3[21] = y4;
        fArr3[22] = f2;
        fArr3[23] = u2;
        fArr3[24] = v;
        fArr3[25] = x12;
        fArr3[26] = y12;
        fArr3[27] = f2;
        fArr3[28] = u;
        fArr3[29] = v;
        add(texture, fArr3, 0, 30);
    }

    public void add(TextureRegion region, float x, float y) {
        add(region, x, y, region.getRegionWidth(), region.getRegionHeight());
    }

    public void add(TextureRegion region, float x, float y, float width, float height) {
        float fx2 = x + width;
        float fy2 = y + height;
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        float[] fArr = tempVertices;
        fArr[0] = x;
        fArr[1] = y;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x;
        fArr[6] = fy2;
        fArr[7] = f;
        fArr[8] = u;
        fArr[9] = v2;
        fArr[10] = fx2;
        fArr[11] = fy2;
        fArr[12] = f;
        fArr[13] = u2;
        fArr[14] = v2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = fx2;
            fArr2[16] = y;
            fArr2[17] = this.colorPacked;
            fArr2[18] = u2;
            fArr2[19] = v;
            add(region.texture, tempVertices, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = fx2;
        fArr3[16] = fy2;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = u2;
        fArr3[19] = v2;
        fArr3[20] = fx2;
        fArr3[21] = y;
        fArr3[22] = f2;
        fArr3[23] = u2;
        fArr3[24] = v;
        fArr3[25] = x;
        fArr3[26] = y;
        fArr3[27] = f2;
        fArr3[28] = u;
        fArr3[29] = v;
        add(region.texture, tempVertices, 0, 30);
    }

    public void add(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        float worldOriginX = x + originX;
        float worldOriginY = y + originY;
        float fx = -originX;
        float fy = -originY;
        float fx2 = width - originX;
        float fy2 = height - originY;
        if (scaleX != 1.0f || scaleY != 1.0f) {
            fx *= scaleX;
            fy *= scaleY;
            fx2 *= scaleX;
            fy2 *= scaleY;
        }
        float p1x = fx;
        float p1y = fy;
        float p2x = fx;
        float p2y = fy2;
        float p3x = fx2;
        float p3y = fy2;
        float p4x = fx2;
        float p4y = fy;
        if (rotation != 0.0f) {
            float cos2 = MathUtils.cosDeg(rotation);
            float sin = MathUtils.sinDeg(rotation);
            x1 = (cos2 * p1x) - (sin * p1y);
            y1 = (sin * p1x) + (cos2 * p1y);
            x2 = (cos2 * p2x) - (sin * p2y);
            y2 = (sin * p2x) + (cos2 * p2y);
            x3 = (cos2 * p3x) - (sin * p3y);
            y3 = (sin * p3x) + (cos2 * p3y);
            x4 = x1 + (x3 - x2);
            cos = y3 - (y2 - y1);
        } else {
            x1 = p1x;
            y1 = p1y;
            x2 = p2x;
            y2 = p2y;
            x3 = p3x;
            y3 = p3y;
            x4 = p4x;
            cos = p4y;
        }
        float x12 = x1 + worldOriginX;
        float y12 = y1 + worldOriginY;
        float x22 = x2 + worldOriginX;
        float y22 = y2 + worldOriginY;
        float x32 = x3 + worldOriginX;
        float y32 = y3 + worldOriginY;
        float x42 = x4 + worldOriginX;
        float y4 = cos + worldOriginY;
        float u = region.u;
        float v = region.v2;
        float worldOriginX2 = region.u2;
        float worldOriginY2 = region.v;
        float[] fArr = tempVertices;
        fArr[0] = x12;
        fArr[1] = y12;
        float f = this.colorPacked;
        fArr[2] = f;
        fArr[3] = u;
        fArr[4] = v;
        fArr[5] = x22;
        fArr[6] = y22;
        fArr[7] = f;
        fArr[8] = u;
        fArr[9] = worldOriginY2;
        fArr[10] = x32;
        fArr[11] = y32;
        fArr[12] = f;
        fArr[13] = worldOriginX2;
        fArr[14] = worldOriginY2;
        if (this.mesh.getNumIndices() > 0) {
            float[] fArr2 = tempVertices;
            fArr2[15] = x42;
            fArr2[16] = y4;
            fArr2[17] = this.colorPacked;
            fArr2[18] = worldOriginX2;
            fArr2[19] = v;
            add(region.texture, tempVertices, 0, 20);
            return;
        }
        float[] fArr3 = tempVertices;
        fArr3[15] = x32;
        fArr3[16] = y32;
        float f2 = this.colorPacked;
        fArr3[17] = f2;
        fArr3[18] = worldOriginX2;
        fArr3[19] = worldOriginY2;
        fArr3[20] = x42;
        fArr3[21] = y4;
        fArr3[22] = f2;
        fArr3[23] = worldOriginX2;
        fArr3[24] = v;
        fArr3[25] = x12;
        fArr3[26] = y12;
        fArr3[27] = f2;
        fArr3[28] = u;
        fArr3[29] = v;
        add(region.texture, tempVertices, 0, 30);
    }

    public void add(Sprite sprite) {
        if (this.mesh.getNumIndices() > 0) {
            add(sprite.getTexture(), sprite.getVertices(), 0, 20);
            return;
        }
        float[] spriteVertices = sprite.getVertices();
        System.arraycopy(spriteVertices, 0, tempVertices, 0, 15);
        System.arraycopy(spriteVertices, 10, tempVertices, 15, 5);
        System.arraycopy(spriteVertices, 15, tempVertices, 20, 5);
        System.arraycopy(spriteVertices, 0, tempVertices, 25, 5);
        add(sprite.getTexture(), tempVertices, 0, 30);
    }

    public void begin() {
        if (this.drawing) {
            throw new IllegalStateException("end must be called before begin.");
        }
        if (this.currentCache != null) {
            throw new IllegalStateException("endCache must be called before begin");
        }
        this.renderCalls = 0;
        this.combinedMatrix.set(this.projectionMatrix).mul(this.transformMatrix);
        Gdx.gl20.glDepthMask(false);
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram != null) {
            shaderProgram.bind();
            this.customShader.setUniformMatrix("u_proj", this.projectionMatrix);
            this.customShader.setUniformMatrix("u_trans", this.transformMatrix);
            this.customShader.setUniformMatrix("u_projTrans", this.combinedMatrix);
            this.customShader.setUniformi("u_texture", 0);
            this.mesh.bind(this.customShader);
        } else {
            this.shader.bind();
            this.shader.setUniformMatrix("u_projectionViewMatrix", this.combinedMatrix);
            this.shader.setUniformi("u_texture", 0);
            this.mesh.bind(this.shader);
        }
        this.drawing = true;
    }

    public void end() {
        if (!this.drawing) {
            throw new IllegalStateException("begin must be called before end.");
        }
        this.drawing = false;
        GL20 gl = Gdx.gl20;
        gl.glDepthMask(true);
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram != null) {
            this.mesh.unbind(shaderProgram);
        } else {
            this.mesh.unbind(this.shader);
        }
    }

    public void draw(int cacheID) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteCache.begin must be called before draw.");
        }
        Cache cache = this.caches.get(cacheID);
        int verticesPerImage = this.mesh.getNumIndices() > 0 ? 4 : 6;
        int offset = (cache.offset / (verticesPerImage * 5)) * 6;
        Texture[] textures = cache.textures;
        int[] counts = cache.counts;
        int textureCount = cache.textureCount;
        for (int i = 0; i < textureCount; i++) {
            int count = counts[i];
            textures[i].bind();
            ShaderProgram shaderProgram = this.customShader;
            if (shaderProgram != null) {
                this.mesh.render(shaderProgram, 4, offset, count);
            } else {
                this.mesh.render(this.shader, 4, offset, count);
            }
            offset += count;
        }
        this.renderCalls += textureCount;
        this.totalRenderCalls += textureCount;
    }

    public void draw(int cacheID, int offset, int length) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteCache.begin must be called before draw.");
        }
        Cache cache = this.caches.get(cacheID);
        int verticesPerImage = this.mesh.getNumIndices() > 0 ? 4 : 6;
        int offset2 = ((cache.offset / (verticesPerImage * 5)) * 6) + (offset * 6);
        int length2 = length * 6;
        Texture[] textures = cache.textures;
        int[] counts = cache.counts;
        int textureCount = cache.textureCount;
        int i = 0;
        while (i < textureCount) {
            textures[i].bind();
            int count = counts[i];
            if (count > length2) {
                i = textureCount;
                count = length2;
            } else {
                length2 -= count;
            }
            ShaderProgram shaderProgram = this.customShader;
            if (shaderProgram != null) {
                this.mesh.render(shaderProgram, 4, offset2, count);
            } else {
                this.mesh.render(this.shader, 4, offset2, count);
            }
            offset2 += count;
            i++;
        }
        this.renderCalls += cache.textureCount;
        this.totalRenderCalls += textureCount;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.mesh.dispose();
        ShaderProgram shaderProgram = this.shader;
        if (shaderProgram != null) {
            shaderProgram.dispose();
        }
    }

    public Matrix4 getProjectionMatrix() {
        return this.projectionMatrix;
    }

    public void setProjectionMatrix(Matrix4 projection) {
        if (this.drawing) {
            throw new IllegalStateException("Can't set the matrix within begin/end.");
        }
        this.projectionMatrix.set(projection);
    }

    public Matrix4 getTransformMatrix() {
        return this.transformMatrix;
    }

    public void setTransformMatrix(Matrix4 transform) {
        if (this.drawing) {
            throw new IllegalStateException("Can't set the matrix within begin/end.");
        }
        this.transformMatrix.set(transform);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Cache {
        int[] counts;
        final int id;
        int maxCount;
        final int offset;
        int textureCount;
        Texture[] textures;

        public Cache(int id, int offset) {
            this.id = id;
            this.offset = offset;
        }
    }

    static ShaderProgram createDefaultShader() {
        ShaderProgram shader = new ShaderProgram("attribute vec4 a_position;\nattribute vec4 a_color;\nattribute vec2 a_texCoord0;\nuniform mat4 u_projectionViewMatrix;\nvarying vec4 v_color;\nvarying vec2 v_texCoords;\n\nvoid main()\n{\n   v_color = a_color;\n   v_color.a = v_color.a * (255.0/254.0);\n   v_texCoords = a_texCoord0;\n   gl_Position =  u_projectionViewMatrix * a_position;\n}\n", "#ifdef GL_ES\nprecision mediump float;\n#endif\nvarying vec4 v_color;\nvarying vec2 v_texCoords;\nuniform sampler2D u_texture;\nvoid main()\n{\n  gl_FragColor = v_color * texture2D(u_texture, v_texCoords);\n}");
        if (!shader.isCompiled()) {
            throw new IllegalArgumentException("Error compiling shader: " + shader.getLog());
        }
        return shader;
    }

    public void setShader(ShaderProgram shader) {
        this.customShader = shader;
    }

    public ShaderProgram getCustomShader() {
        return this.customShader;
    }

    public boolean isDrawing() {
        return this.drawing;
    }
}