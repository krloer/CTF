package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.Affine2;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Matrix4;

/* loaded from: classes.dex */
public class PolygonSpriteBatch implements PolygonBatch {
    private int blendDstFunc;
    private int blendDstFuncAlpha;
    private int blendSrcFunc;
    private int blendSrcFuncAlpha;
    private boolean blendingDisabled;
    private final Color color;
    float colorPacked;
    private final Matrix4 combinedMatrix;
    private ShaderProgram customShader;
    private boolean drawing;
    private float invTexHeight;
    private float invTexWidth;
    private Texture lastTexture;
    public int maxTrianglesInBatch;
    private Mesh mesh;
    private boolean ownsShader;
    private final Matrix4 projectionMatrix;
    public int renderCalls;
    private final ShaderProgram shader;
    public int totalRenderCalls;
    private final Matrix4 transformMatrix;
    private int triangleIndex;
    private final short[] triangles;
    private int vertexIndex;
    private final float[] vertices;

    public PolygonSpriteBatch() {
        this(2000, null);
    }

    public PolygonSpriteBatch(int size) {
        this(size, size * 2, null);
    }

    public PolygonSpriteBatch(int size, ShaderProgram defaultShader) {
        this(size, size * 2, defaultShader);
    }

    public PolygonSpriteBatch(int maxVertices, int maxTriangles, ShaderProgram defaultShader) {
        this.invTexWidth = 0.0f;
        this.invTexHeight = 0.0f;
        this.transformMatrix = new Matrix4();
        this.projectionMatrix = new Matrix4();
        this.combinedMatrix = new Matrix4();
        this.blendSrcFunc = GL20.GL_SRC_ALPHA;
        this.blendDstFunc = GL20.GL_ONE_MINUS_SRC_ALPHA;
        this.blendSrcFuncAlpha = GL20.GL_SRC_ALPHA;
        this.blendDstFuncAlpha = GL20.GL_ONE_MINUS_SRC_ALPHA;
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.colorPacked = Color.WHITE_FLOAT_BITS;
        this.renderCalls = 0;
        this.totalRenderCalls = 0;
        this.maxTrianglesInBatch = 0;
        if (maxVertices > 32767) {
            throw new IllegalArgumentException("Can't have more than 32767 vertices per batch: " + maxVertices);
        }
        Mesh.VertexDataType vertexDataType = Mesh.VertexDataType.VertexArray;
        this.mesh = new Mesh(Gdx.gl30 != null ? Mesh.VertexDataType.VertexBufferObjectWithVAO : vertexDataType, false, maxVertices, maxTriangles * 3, new VertexAttribute(1, 2, ShaderProgram.POSITION_ATTRIBUTE), new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE), new VertexAttribute(16, 2, "a_texCoord0"));
        this.vertices = new float[maxVertices * 5];
        this.triangles = new short[maxTriangles * 3];
        if (defaultShader == null) {
            this.shader = SpriteBatch.createDefaultShader();
            this.ownsShader = true;
        } else {
            this.shader = defaultShader;
        }
        this.projectionMatrix.setToOrtho2D(0.0f, 0.0f, Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void begin() {
        if (this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.end must be called before begin.");
        }
        this.renderCalls = 0;
        Gdx.gl.glDepthMask(false);
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram != null) {
            shaderProgram.bind();
        } else {
            this.shader.bind();
        }
        setupMatrices();
        this.drawing = true;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void end() {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before end.");
        }
        if (this.vertexIndex > 0) {
            flush();
        }
        this.lastTexture = null;
        this.drawing = false;
        GL20 gl = Gdx.gl;
        gl.glDepthMask(true);
        if (isBlendingEnabled()) {
            gl.glDisable(GL20.GL_BLEND);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setColor(Color tint) {
        this.color.set(tint);
        this.colorPacked = tint.toFloatBits();
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        this.colorPacked = this.color.toFloatBits();
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setPackedColor(float packedColor) {
        Color.abgr8888ToColor(this.color, packedColor);
        this.colorPacked = packedColor;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public Color getColor() {
        return this.color;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public float getPackedColor() {
        return this.colorPacked;
    }

    @Override // com.badlogic.gdx.graphics.g2d.PolygonBatch
    public void draw(PolygonRegion region, float x, float y) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        short[] regionTriangles = region.triangles;
        int regionTrianglesLength = regionTriangles.length;
        float[] regionVertices = region.vertices;
        int regionVerticesLength = regionVertices.length;
        Texture texture = region.region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + regionTrianglesLength > triangles.length || this.vertexIndex + ((regionVerticesLength * 5) / 2) > this.vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int vertexIndex = this.vertexIndex;
        int startVertex = vertexIndex / 5;
        int i = 0;
        while (i < regionTrianglesLength) {
            triangles[triangleIndex] = (short) (regionTriangles[i] + startVertex);
            i++;
            triangleIndex++;
        }
        this.triangleIndex = triangleIndex;
        float[] vertices = this.vertices;
        float color = this.colorPacked;
        float[] textureCoords = region.textureCoords;
        int i2 = 0;
        while (i2 < regionVerticesLength) {
            int vertexIndex2 = vertexIndex + 1;
            vertices[vertexIndex] = regionVertices[i2] + x;
            int vertexIndex3 = vertexIndex2 + 1;
            vertices[vertexIndex2] = regionVertices[i2 + 1] + y;
            int vertexIndex4 = vertexIndex3 + 1;
            vertices[vertexIndex3] = color;
            int vertexIndex5 = vertexIndex4 + 1;
            vertices[vertexIndex4] = textureCoords[i2];
            vertices[vertexIndex5] = textureCoords[i2 + 1];
            i2 += 2;
            vertexIndex = vertexIndex5 + 1;
        }
        this.vertexIndex = vertexIndex;
    }

    @Override // com.badlogic.gdx.graphics.g2d.PolygonBatch
    public void draw(PolygonRegion region, float x, float y, float width, float height) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        short[] regionTriangles = region.triangles;
        int regionTrianglesLength = regionTriangles.length;
        float[] regionVertices = region.vertices;
        int regionVerticesLength = regionVertices.length;
        TextureRegion textureRegion = region.region;
        Texture texture = textureRegion.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + regionTrianglesLength > triangles.length || this.vertexIndex + ((regionVerticesLength * 5) / 2) > this.vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int vertexIndex = this.vertexIndex;
        int startVertex = vertexIndex / 5;
        int i = 0;
        int n = regionTriangles.length;
        while (i < n) {
            triangles[triangleIndex] = (short) (regionTriangles[i] + startVertex);
            i++;
            triangleIndex++;
        }
        this.triangleIndex = triangleIndex;
        float[] vertices = this.vertices;
        float color = this.colorPacked;
        float[] textureCoords = region.textureCoords;
        float sX = width / textureRegion.regionWidth;
        float sY = height / textureRegion.regionHeight;
        int vertexIndex2 = vertexIndex;
        int vertexIndex3 = 0;
        while (vertexIndex3 < regionVerticesLength) {
            int vertexIndex4 = vertexIndex2 + 1;
            vertices[vertexIndex2] = (regionVertices[vertexIndex3] * sX) + x;
            int vertexIndex5 = vertexIndex4 + 1;
            vertices[vertexIndex4] = (regionVertices[vertexIndex3 + 1] * sY) + y;
            int vertexIndex6 = vertexIndex5 + 1;
            vertices[vertexIndex5] = color;
            int vertexIndex7 = vertexIndex6 + 1;
            vertices[vertexIndex6] = textureCoords[vertexIndex3];
            vertices[vertexIndex7] = textureCoords[vertexIndex3 + 1];
            vertexIndex3 += 2;
            vertexIndex2 = vertexIndex7 + 1;
        }
        this.vertexIndex = vertexIndex2;
    }

    @Override // com.badlogic.gdx.graphics.g2d.PolygonBatch
    public void draw(PolygonRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        short[] regionTriangles = region.triangles;
        int regionTrianglesLength = regionTriangles.length;
        float[] regionVertices = region.vertices;
        int regionVerticesLength = regionVertices.length;
        TextureRegion textureRegion = region.region;
        Texture texture = textureRegion.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + regionTrianglesLength > triangles.length || this.vertexIndex + ((regionVerticesLength * 5) / 2) > this.vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int vertexIndex = this.vertexIndex;
        int startVertex = vertexIndex / 5;
        int i = 0;
        while (i < regionTrianglesLength) {
            triangles[triangleIndex] = (short) (regionTriangles[i] + startVertex);
            i++;
            triangleIndex++;
        }
        this.triangleIndex = triangleIndex;
        float[] vertices = this.vertices;
        float color = this.colorPacked;
        float[] textureCoords = region.textureCoords;
        float worldOriginX = x + originX;
        float worldOriginY = y + originY;
        float sX = width / textureRegion.regionWidth;
        float sY = height / textureRegion.regionHeight;
        float cos = MathUtils.cosDeg(rotation);
        float sin = MathUtils.sinDeg(rotation);
        int vertexIndex2 = vertexIndex;
        int vertexIndex3 = 0;
        while (vertexIndex3 < regionVerticesLength) {
            float fx = ((regionVertices[vertexIndex3] * sX) - originX) * scaleX;
            float fy = ((regionVertices[vertexIndex3 + 1] * sY) - originY) * scaleY;
            int vertexIndex4 = vertexIndex2 + 1;
            vertices[vertexIndex2] = ((cos * fx) - (sin * fy)) + worldOriginX;
            int vertexIndex5 = vertexIndex4 + 1;
            vertices[vertexIndex4] = (sin * fx) + (cos * fy) + worldOriginY;
            int vertexIndex6 = vertexIndex5 + 1;
            vertices[vertexIndex5] = color;
            int vertexIndex7 = vertexIndex6 + 1;
            vertices[vertexIndex6] = textureCoords[vertexIndex3];
            vertices[vertexIndex7] = textureCoords[vertexIndex3 + 1];
            vertexIndex3 += 2;
            vertexIndex2 = vertexIndex7 + 1;
        }
        this.vertexIndex = vertexIndex2;
    }

    @Override // com.badlogic.gdx.graphics.g2d.PolygonBatch
    public void draw(Texture texture, float[] polygonVertices, int verticesOffset, int verticesCount, short[] polygonTriangles, int trianglesOffset, int trianglesCount) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + trianglesCount > triangles.length || this.vertexIndex + verticesCount > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int vertexIndex = this.vertexIndex;
        int startVertex = vertexIndex / 5;
        int i = trianglesOffset;
        int n = i + trianglesCount;
        while (i < n) {
            triangles[triangleIndex] = (short) (polygonTriangles[i] + startVertex);
            i++;
            triangleIndex++;
        }
        this.triangleIndex = triangleIndex;
        System.arraycopy(polygonVertices, verticesOffset, vertices, vertexIndex, verticesCount);
        this.vertexIndex += verticesCount;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
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
        float f = this.invTexWidth;
        float u = srcX * f;
        float f2 = this.invTexHeight;
        float v = (srcY + srcHeight) * f2;
        float u2 = (srcX + srcWidth) * f;
        float v2 = srcY * f2;
        if (flipX) {
            u = u2;
            u2 = u;
        }
        if (flipY) {
            v = v2;
            v2 = v;
        }
        float tmp = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x12;
        int idx3 = idx2 + 1;
        vertices[idx2] = y12;
        int idx4 = idx3 + 1;
        vertices[idx3] = tmp;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x22;
        int idx8 = idx7 + 1;
        vertices[idx7] = y22;
        int idx9 = idx8 + 1;
        vertices[idx8] = tmp;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = x32;
        int idx13 = idx12 + 1;
        vertices[idx12] = y32;
        int idx14 = idx13 + 1;
        vertices[idx13] = tmp;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = x42;
        int idx18 = idx17 + 1;
        vertices[idx17] = y4;
        int idx19 = idx18 + 1;
        vertices[idx18] = tmp;
        int idx20 = idx19 + 1;
        vertices[idx19] = u2;
        vertices[idx20] = v;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float f = this.invTexWidth;
        float u = srcX * f;
        float f2 = this.invTexHeight;
        float v = (srcY + srcHeight) * f2;
        float u2 = (srcX + srcWidth) * f;
        float v2 = srcY * f2;
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
        float tmp = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x;
        int idx3 = idx2 + 1;
        vertices[idx2] = y;
        int idx4 = idx3 + 1;
        vertices[idx3] = tmp;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x;
        int idx8 = idx7 + 1;
        vertices[idx7] = fy2;
        int idx9 = idx8 + 1;
        vertices[idx8] = tmp;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = fx2;
        int idx13 = idx12 + 1;
        vertices[idx12] = fy2;
        int idx14 = idx13 + 1;
        vertices[idx13] = tmp;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = fx2;
        int idx18 = idx17 + 1;
        vertices[idx17] = y;
        int idx19 = idx18 + 1;
        vertices[idx18] = tmp;
        int idx20 = idx19 + 1;
        vertices[idx19] = u2;
        vertices[idx20] = v;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, int srcX, int srcY, int srcWidth, int srcHeight) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float f = this.invTexWidth;
        float u = srcX * f;
        float f2 = this.invTexHeight;
        float v = (srcY + srcHeight) * f2;
        float u2 = (srcX + srcWidth) * f;
        float v2 = srcY * f2;
        float fx2 = x + srcWidth;
        float fy2 = y + srcHeight;
        float color = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x;
        int idx3 = idx2 + 1;
        vertices[idx2] = y;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x;
        int idx8 = idx7 + 1;
        vertices[idx7] = fy2;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = fx2;
        int idx13 = idx12 + 1;
        vertices[idx12] = fy2;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = fx2;
        int idx18 = idx17 + 1;
        vertices[idx17] = y;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        int idx20 = idx19 + 1;
        vertices[idx19] = u2;
        vertices[idx20] = v;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, float u, float v, float u2, float v2) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float fx2 = x + width;
        float fy2 = y + height;
        float color = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x;
        int idx3 = idx2 + 1;
        vertices[idx2] = y;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x;
        int idx8 = idx7 + 1;
        vertices[idx7] = fy2;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = fx2;
        int idx13 = idx12 + 1;
        vertices[idx12] = fy2;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = fx2;
        int idx18 = idx17 + 1;
        vertices[idx17] = y;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        int idx20 = idx19 + 1;
        vertices[idx19] = u2;
        vertices[idx20] = v;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y) {
        draw(texture, x, y, texture.getWidth(), texture.getHeight());
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float fx2 = x + width;
        float fy2 = y + height;
        float color = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x;
        int idx3 = idx2 + 1;
        vertices[idx2] = y;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = 0.0f;
        int idx6 = idx5 + 1;
        vertices[idx5] = 1.0f;
        int idx7 = idx6 + 1;
        vertices[idx6] = x;
        int idx8 = idx7 + 1;
        vertices[idx7] = fy2;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = 0.0f;
        int idx11 = idx10 + 1;
        vertices[idx10] = 0.0f;
        int idx12 = idx11 + 1;
        vertices[idx11] = fx2;
        int idx13 = idx12 + 1;
        vertices[idx12] = fy2;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = 1.0f;
        int idx16 = idx15 + 1;
        vertices[idx15] = 0.0f;
        int idx17 = idx16 + 1;
        vertices[idx16] = fx2;
        int idx18 = idx17 + 1;
        vertices[idx17] = y;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        int idx20 = idx19 + 1;
        vertices[idx19] = 1.0f;
        vertices[idx20] = 1.0f;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float[] spriteVertices, int offset, int count) {
        int batch;
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        int triangleCount = (count / 20) * 6;
        if (texture != this.lastTexture) {
            switchTexture(texture);
            batch = Math.min(Math.min(count, vertices.length - (vertices.length % 20)), (triangles.length / 6) * 20);
            triangleCount = (batch / 20) * 6;
        } else if (this.triangleIndex + triangleCount > triangles.length || this.vertexIndex + count > vertices.length) {
            flush();
            batch = Math.min(Math.min(count, vertices.length - (vertices.length % 20)), (triangles.length / 6) * 20);
            triangleCount = (batch / 20) * 6;
        } else {
            batch = count;
        }
        int vertexIndex = this.vertexIndex;
        short vertex = (short) (vertexIndex / 5);
        int triangleIndex = this.triangleIndex;
        int n = triangleIndex + triangleCount;
        while (triangleIndex < n) {
            triangles[triangleIndex] = vertex;
            triangles[triangleIndex + 1] = (short) (vertex + 1);
            triangles[triangleIndex + 2] = (short) (vertex + 2);
            triangles[triangleIndex + 3] = (short) (vertex + 2);
            triangles[triangleIndex + 4] = (short) (vertex + 3);
            triangles[triangleIndex + 5] = vertex;
            triangleIndex += 6;
            vertex = (short) (vertex + 4);
        }
        while (true) {
            System.arraycopy(spriteVertices, offset, vertices, vertexIndex, batch);
            this.vertexIndex = vertexIndex + batch;
            this.triangleIndex = triangleIndex;
            count -= batch;
            if (count != 0) {
                offset += batch;
                flush();
                vertexIndex = 0;
                if (batch > count) {
                    batch = Math.min(count, (triangles.length / 6) * 20);
                    triangleIndex = (batch / 20) * 6;
                }
            } else {
                return;
            }
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y) {
        draw(region, x, y, region.getRegionWidth(), region.getRegionHeight());
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float width, float height) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float fx2 = x + width;
        float fy2 = y + height;
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        float color = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x;
        int idx3 = idx2 + 1;
        vertices[idx2] = y;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x;
        int idx8 = idx7 + 1;
        vertices[idx7] = fy2;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = fx2;
        int idx13 = idx12 + 1;
        vertices[idx12] = fy2;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = fx2;
        int idx18 = idx17 + 1;
        vertices[idx17] = y;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        int idx20 = idx19 + 1;
        vertices[idx19] = u2;
        vertices[idx20] = v;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
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
        float y4 = cos + worldOriginY;
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        float color = this.colorPacked;
        int triangleIndex7 = this.vertexIndex;
        int idx = triangleIndex7 + 1;
        vertices[triangleIndex7] = x1 + worldOriginX;
        int idx2 = idx + 1;
        vertices[idx] = y1 + worldOriginY;
        int idx3 = idx2 + 1;
        vertices[idx2] = color;
        int idx4 = idx3 + 1;
        vertices[idx3] = u;
        int idx5 = idx4 + 1;
        vertices[idx4] = v;
        int idx6 = idx5 + 1;
        vertices[idx5] = x2 + worldOriginX;
        int idx7 = idx6 + 1;
        vertices[idx6] = y2 + worldOriginY;
        int idx8 = idx7 + 1;
        vertices[idx7] = color;
        int idx9 = idx8 + 1;
        vertices[idx8] = u;
        int idx10 = idx9 + 1;
        vertices[idx9] = v2;
        int idx11 = idx10 + 1;
        vertices[idx10] = x3 + worldOriginX;
        int idx12 = idx11 + 1;
        vertices[idx11] = y3 + worldOriginY;
        int idx13 = idx12 + 1;
        vertices[idx12] = color;
        int idx14 = idx13 + 1;
        vertices[idx13] = u2;
        int idx15 = idx14 + 1;
        vertices[idx14] = v2;
        int idx16 = idx15 + 1;
        vertices[idx15] = x4 + worldOriginX;
        int idx17 = idx16 + 1;
        vertices[idx16] = y4;
        int idx18 = idx17 + 1;
        vertices[idx17] = color;
        int idx19 = idx18 + 1;
        vertices[idx18] = u2;
        vertices[idx19] = v;
        this.vertexIndex = idx19 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, boolean clockwise) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        float u1;
        float v1;
        float u2;
        float v2;
        float u3;
        float v3;
        float u4;
        float u42;
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
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
        if (clockwise) {
            float u12 = region.u2;
            u1 = u12;
            float u13 = region.v2;
            v1 = u13;
            float v12 = region.u;
            u2 = v12;
            float u22 = region.v2;
            v2 = u22;
            float v22 = region.u;
            u3 = v22;
            float u32 = region.v;
            v3 = u32;
            float v32 = region.u2;
            u4 = v32;
            u42 = region.v;
        } else {
            float v4 = region.u;
            u1 = v4;
            float u14 = region.v;
            v1 = u14;
            float v13 = region.u2;
            u2 = v13;
            float u23 = region.v;
            v2 = u23;
            float v23 = region.u2;
            u3 = v23;
            float u33 = region.v2;
            v3 = u33;
            float v33 = region.u;
            u4 = v33;
            u42 = region.v2;
        }
        float color = this.colorPacked;
        int idx = this.vertexIndex;
        int idx2 = idx + 1;
        vertices[idx] = x12;
        int idx3 = idx2 + 1;
        vertices[idx2] = y12;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = u1;
        int idx6 = idx5 + 1;
        vertices[idx5] = v1;
        int idx7 = idx6 + 1;
        vertices[idx6] = x22;
        int idx8 = idx7 + 1;
        vertices[idx7] = y22;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = u2;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = x32;
        int idx13 = idx12 + 1;
        vertices[idx12] = y32;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = u3;
        int idx16 = idx15 + 1;
        vertices[idx15] = v3;
        int idx17 = idx16 + 1;
        vertices[idx16] = x42;
        int idx18 = idx17 + 1;
        vertices[idx17] = y4;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        int idx20 = idx19 + 1;
        vertices[idx19] = u4;
        vertices[idx20] = u42;
        this.vertexIndex = idx20 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float width, float height, Affine2 transform) {
        if (!this.drawing) {
            throw new IllegalStateException("PolygonSpriteBatch.begin must be called before draw.");
        }
        short[] triangles = this.triangles;
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.triangleIndex + 6 > triangles.length || this.vertexIndex + 20 > vertices.length) {
            flush();
        }
        int triangleIndex = this.triangleIndex;
        int startVertex = this.vertexIndex / 5;
        int triangleIndex2 = triangleIndex + 1;
        triangles[triangleIndex] = (short) startVertex;
        int triangleIndex3 = triangleIndex2 + 1;
        triangles[triangleIndex2] = (short) (startVertex + 1);
        int triangleIndex4 = triangleIndex3 + 1;
        triangles[triangleIndex3] = (short) (startVertex + 2);
        int triangleIndex5 = triangleIndex4 + 1;
        triangles[triangleIndex4] = (short) (startVertex + 2);
        int triangleIndex6 = triangleIndex5 + 1;
        triangles[triangleIndex5] = (short) (startVertex + 3);
        triangles[triangleIndex6] = (short) startVertex;
        this.triangleIndex = triangleIndex6 + 1;
        float x1 = transform.m02;
        float y1 = transform.m12;
        float x2 = (transform.m01 * height) + transform.m02;
        float y2 = (transform.m11 * height) + transform.m12;
        float x3 = (transform.m00 * width) + (transform.m01 * height) + transform.m02;
        float y3 = (transform.m10 * width) + (transform.m11 * height) + transform.m12;
        float x4 = (transform.m00 * width) + transform.m02;
        float y4 = (transform.m10 * width) + transform.m12;
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        float color = this.colorPacked;
        int startVertex2 = this.vertexIndex;
        int idx = startVertex2 + 1;
        vertices[startVertex2] = x1;
        int idx2 = idx + 1;
        vertices[idx] = y1;
        int idx3 = idx2 + 1;
        vertices[idx2] = color;
        int idx4 = idx3 + 1;
        vertices[idx3] = u;
        int idx5 = idx4 + 1;
        vertices[idx4] = v;
        int idx6 = idx5 + 1;
        vertices[idx5] = x2;
        int idx7 = idx6 + 1;
        vertices[idx6] = y2;
        int idx8 = idx7 + 1;
        vertices[idx7] = color;
        int idx9 = idx8 + 1;
        vertices[idx8] = u;
        int idx10 = idx9 + 1;
        vertices[idx9] = v2;
        int idx11 = idx10 + 1;
        vertices[idx10] = x3;
        int idx12 = idx11 + 1;
        vertices[idx11] = y3;
        int idx13 = idx12 + 1;
        vertices[idx12] = color;
        int idx14 = idx13 + 1;
        vertices[idx13] = u2;
        int idx15 = idx14 + 1;
        vertices[idx14] = v2;
        int idx16 = idx15 + 1;
        vertices[idx15] = x4;
        int idx17 = idx16 + 1;
        vertices[idx16] = y4;
        int idx18 = idx17 + 1;
        vertices[idx17] = color;
        int idx19 = idx18 + 1;
        vertices[idx18] = u2;
        vertices[idx19] = v;
        this.vertexIndex = idx19 + 1;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void flush() {
        if (this.vertexIndex == 0) {
            return;
        }
        this.renderCalls++;
        this.totalRenderCalls++;
        int trianglesInBatch = this.triangleIndex;
        if (trianglesInBatch > this.maxTrianglesInBatch) {
            this.maxTrianglesInBatch = trianglesInBatch;
        }
        this.lastTexture.bind();
        Mesh mesh = this.mesh;
        mesh.setVertices(this.vertices, 0, this.vertexIndex);
        mesh.setIndices(this.triangles, 0, trianglesInBatch);
        if (this.blendingDisabled) {
            Gdx.gl.glDisable(GL20.GL_BLEND);
        } else {
            Gdx.gl.glEnable(GL20.GL_BLEND);
            if (this.blendSrcFunc != -1) {
                Gdx.gl.glBlendFuncSeparate(this.blendSrcFunc, this.blendDstFunc, this.blendSrcFuncAlpha, this.blendDstFuncAlpha);
            }
        }
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram == null) {
            shaderProgram = this.shader;
        }
        mesh.render(shaderProgram, 4, 0, trianglesInBatch);
        this.vertexIndex = 0;
        this.triangleIndex = 0;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void disableBlending() {
        flush();
        this.blendingDisabled = true;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void enableBlending() {
        flush();
        this.blendingDisabled = false;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setBlendFunction(int srcFunc, int dstFunc) {
        setBlendFunctionSeparate(srcFunc, dstFunc, srcFunc, dstFunc);
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setBlendFunctionSeparate(int srcFuncColor, int dstFuncColor, int srcFuncAlpha, int dstFuncAlpha) {
        if (this.blendSrcFunc == srcFuncColor && this.blendDstFunc == dstFuncColor && this.blendSrcFuncAlpha == srcFuncAlpha && this.blendDstFuncAlpha == dstFuncAlpha) {
            return;
        }
        flush();
        this.blendSrcFunc = srcFuncColor;
        this.blendDstFunc = dstFuncColor;
        this.blendSrcFuncAlpha = srcFuncAlpha;
        this.blendDstFuncAlpha = dstFuncAlpha;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public int getBlendSrcFunc() {
        return this.blendSrcFunc;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public int getBlendDstFunc() {
        return this.blendDstFunc;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public int getBlendSrcFuncAlpha() {
        return this.blendSrcFuncAlpha;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public int getBlendDstFuncAlpha() {
        return this.blendDstFuncAlpha;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        ShaderProgram shaderProgram;
        this.mesh.dispose();
        if (!this.ownsShader || (shaderProgram = this.shader) == null) {
            return;
        }
        shaderProgram.dispose();
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public Matrix4 getProjectionMatrix() {
        return this.projectionMatrix;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public Matrix4 getTransformMatrix() {
        return this.transformMatrix;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setProjectionMatrix(Matrix4 projection) {
        if (this.drawing) {
            flush();
        }
        this.projectionMatrix.set(projection);
        if (this.drawing) {
            setupMatrices();
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setTransformMatrix(Matrix4 transform) {
        if (this.drawing) {
            flush();
        }
        this.transformMatrix.set(transform);
        if (this.drawing) {
            setupMatrices();
        }
    }

    protected void setupMatrices() {
        this.combinedMatrix.set(this.projectionMatrix).mul(this.transformMatrix);
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram != null) {
            shaderProgram.setUniformMatrix("u_projTrans", this.combinedMatrix);
            this.customShader.setUniformi("u_texture", 0);
            return;
        }
        this.shader.setUniformMatrix("u_projTrans", this.combinedMatrix);
        this.shader.setUniformi("u_texture", 0);
    }

    private void switchTexture(Texture texture) {
        flush();
        this.lastTexture = texture;
        this.invTexWidth = 1.0f / texture.getWidth();
        this.invTexHeight = 1.0f / texture.getHeight();
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setShader(ShaderProgram shader) {
        if (this.drawing) {
            flush();
        }
        this.customShader = shader;
        if (this.drawing) {
            ShaderProgram shaderProgram = this.customShader;
            if (shaderProgram != null) {
                shaderProgram.bind();
            } else {
                this.shader.bind();
            }
            setupMatrices();
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public ShaderProgram getShader() {
        ShaderProgram shaderProgram = this.customShader;
        if (shaderProgram == null) {
            return this.shader;
        }
        return shaderProgram;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public boolean isBlendingEnabled() {
        return !this.blendingDisabled;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public boolean isDrawing() {
        return this.drawing;
    }
}