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
public class SpriteBatch implements Batch {
    @Deprecated
    public static Mesh.VertexDataType defaultVertexDataType = Mesh.VertexDataType.VertexArray;
    private int blendDstFunc;
    private int blendDstFuncAlpha;
    private int blendSrcFunc;
    private int blendSrcFuncAlpha;
    private boolean blendingDisabled;
    private final Color color;
    float colorPacked;
    private final Matrix4 combinedMatrix;
    private ShaderProgram customShader;
    boolean drawing;
    int idx;
    float invTexHeight;
    float invTexWidth;
    Texture lastTexture;
    public int maxSpritesInBatch;
    private Mesh mesh;
    private boolean ownsShader;
    private final Matrix4 projectionMatrix;
    public int renderCalls;
    private final ShaderProgram shader;
    public int totalRenderCalls;
    private final Matrix4 transformMatrix;
    final float[] vertices;

    public SpriteBatch() {
        this(1000, null);
    }

    public SpriteBatch(int size) {
        this(size, null);
    }

    public SpriteBatch(int size, ShaderProgram defaultShader) {
        this.idx = 0;
        this.lastTexture = null;
        this.invTexWidth = 0.0f;
        this.invTexHeight = 0.0f;
        this.drawing = false;
        this.transformMatrix = new Matrix4();
        this.projectionMatrix = new Matrix4();
        this.combinedMatrix = new Matrix4();
        this.blendingDisabled = false;
        this.blendSrcFunc = GL20.GL_SRC_ALPHA;
        this.blendDstFunc = GL20.GL_ONE_MINUS_SRC_ALPHA;
        this.blendSrcFuncAlpha = GL20.GL_SRC_ALPHA;
        this.blendDstFuncAlpha = GL20.GL_ONE_MINUS_SRC_ALPHA;
        this.customShader = null;
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.colorPacked = Color.WHITE_FLOAT_BITS;
        this.renderCalls = 0;
        this.totalRenderCalls = 0;
        this.maxSpritesInBatch = 0;
        if (size > 8191) {
            throw new IllegalArgumentException("Can't have more than 8191 sprites per batch: " + size);
        }
        Mesh.VertexDataType vertexDataType = Gdx.gl30 != null ? Mesh.VertexDataType.VertexBufferObjectWithVAO : defaultVertexDataType;
        this.mesh = new Mesh(vertexDataType, false, size * 4, size * 6, new VertexAttribute(1, 2, ShaderProgram.POSITION_ATTRIBUTE), new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE), new VertexAttribute(16, 2, "a_texCoord0"));
        this.projectionMatrix.setToOrtho2D(0.0f, 0.0f, Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
        this.vertices = new float[size * 20];
        int len = size * 6;
        short[] indices = new short[len];
        short j = 0;
        int i = 0;
        while (i < len) {
            indices[i] = j;
            indices[i + 1] = (short) (j + 1);
            indices[i + 2] = (short) (j + 2);
            indices[i + 3] = (short) (j + 2);
            indices[i + 4] = (short) (j + 3);
            indices[i + 5] = j;
            i += 6;
            j = (short) (j + 4);
        }
        this.mesh.setIndices(indices);
        if (defaultShader == null) {
            this.shader = createDefaultShader();
            this.ownsShader = true;
            return;
        }
        this.shader = defaultShader;
    }

    public static ShaderProgram createDefaultShader() {
        ShaderProgram shader = new ShaderProgram("attribute vec4 a_position;\nattribute vec4 a_color;\nattribute vec2 a_texCoord0;\nuniform mat4 u_projTrans;\nvarying vec4 v_color;\nvarying vec2 v_texCoords;\n\nvoid main()\n{\n   v_color = a_color;\n   v_color.a = v_color.a * (255.0/254.0);\n   v_texCoords = a_texCoord0;\n   gl_Position =  u_projTrans * a_position;\n}\n", "#ifdef GL_ES\n#define LOWP lowp\nprecision mediump float;\n#else\n#define LOWP \n#endif\nvarying LOWP vec4 v_color;\nvarying vec2 v_texCoords;\nuniform sampler2D u_texture;\nvoid main()\n{\n  gl_FragColor = v_color * texture2D(u_texture, v_texCoords);\n}");
        if (!shader.isCompiled()) {
            throw new IllegalArgumentException("Error compiling shader: " + shader.getLog());
        }
        return shader;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void begin() {
        if (this.drawing) {
            throw new IllegalStateException("SpriteBatch.end must be called before begin.");
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
            throw new IllegalStateException("SpriteBatch.begin must be called before end.");
        }
        if (this.idx > 0) {
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
    public Color getColor() {
        return this.color;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void setPackedColor(float packedColor) {
        Color.abgr8888ToColor(this.color, packedColor);
        this.colorPacked = packedColor;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public float getPackedColor() {
        return this.colorPacked;
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
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
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
        int idx = this.idx;
        vertices[idx] = x12;
        vertices[idx + 1] = y12;
        vertices[idx + 2] = tmp;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x22;
        vertices[idx + 6] = y22;
        vertices[idx + 7] = tmp;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = x32;
        vertices[idx + 11] = y32;
        vertices[idx + 12] = tmp;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = x42;
        vertices[idx + 16] = y4;
        vertices[idx + 17] = tmp;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
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
        int idx = this.idx;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = tmp;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = tmp;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = tmp;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = tmp;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, int srcX, int srcY, int srcWidth, int srcHeight) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
        float f = this.invTexWidth;
        float u = srcX * f;
        float f2 = this.invTexHeight;
        float v = (srcY + srcHeight) * f2;
        float u2 = (srcX + srcWidth) * f;
        float v2 = srcY * f2;
        float fx2 = x + srcWidth;
        float fy2 = y + srcHeight;
        float color = this.colorPacked;
        int idx = this.idx;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, float u, float v, float u2, float v2) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
        float fx2 = x + width;
        float fy2 = y + height;
        float color = this.colorPacked;
        int idx = this.idx;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y) {
        draw(texture, x, y, texture.getWidth(), texture.getHeight());
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
        float fx2 = x + width;
        float fy2 = y + height;
        float color = this.colorPacked;
        int idx = this.idx;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = color;
        vertices[idx + 3] = 0.0f;
        vertices[idx + 4] = 1.0f;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = color;
        vertices[idx + 8] = 0.0f;
        vertices[idx + 9] = 0.0f;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = color;
        vertices[idx + 13] = 1.0f;
        vertices[idx + 14] = 0.0f;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = color;
        vertices[idx + 18] = 1.0f;
        vertices[idx + 19] = 1.0f;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float[] spriteVertices, int offset, int count) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        int verticesLength = this.vertices.length;
        int remainingVertices = verticesLength;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else {
            remainingVertices -= this.idx;
            if (remainingVertices == 0) {
                flush();
                remainingVertices = verticesLength;
            }
        }
        int copyCount = Math.min(remainingVertices, count);
        System.arraycopy(spriteVertices, offset, this.vertices, this.idx, copyCount);
        this.idx += copyCount;
        int count2 = count - copyCount;
        while (count2 > 0) {
            offset += copyCount;
            flush();
            copyCount = Math.min(verticesLength, count2);
            System.arraycopy(spriteVertices, offset, this.vertices, 0, copyCount);
            this.idx += copyCount;
            count2 -= copyCount;
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y) {
        draw(region, x, y, region.getRegionWidth(), region.getRegionHeight());
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float width, float height) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
        float fx2 = x + width;
        float fy2 = y + height;
        float u = region.u;
        float v = region.v2;
        float u2 = region.u2;
        float v2 = region.v;
        float color = this.colorPacked;
        int idx = this.idx;
        vertices[idx] = x;
        vertices[idx + 1] = y;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x;
        vertices[idx + 6] = fy2;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = fx2;
        vertices[idx + 11] = fy2;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = fx2;
        vertices[idx + 16] = y;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
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
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
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
        float u2 = region.u2;
        float worldOriginX2 = region.v;
        float color = this.colorPacked;
        int idx = this.idx;
        vertices[idx] = x12;
        vertices[idx + 1] = y12;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x22;
        vertices[idx + 6] = y22;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u;
        vertices[idx + 9] = worldOriginX2;
        vertices[idx + 10] = x32;
        vertices[idx + 11] = y32;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = worldOriginX2;
        vertices[idx + 15] = x42;
        vertices[idx + 16] = y4;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
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
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
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
        int idx = this.idx;
        vertices[idx] = x12;
        vertices[idx + 1] = y12;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u1;
        vertices[idx + 4] = v1;
        vertices[idx + 5] = x22;
        vertices[idx + 6] = y22;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u2;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = x32;
        vertices[idx + 11] = y32;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u3;
        vertices[idx + 14] = v3;
        vertices[idx + 15] = x42;
        vertices[idx + 16] = y4;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u4;
        vertices[idx + 19] = u42;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float width, float height, Affine2 transform) {
        if (!this.drawing) {
            throw new IllegalStateException("SpriteBatch.begin must be called before draw.");
        }
        float[] vertices = this.vertices;
        Texture texture = region.texture;
        if (texture != this.lastTexture) {
            switchTexture(texture);
        } else if (this.idx == vertices.length) {
            flush();
        }
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
        int idx = this.idx;
        vertices[idx] = x1;
        vertices[idx + 1] = y1;
        vertices[idx + 2] = color;
        vertices[idx + 3] = u;
        vertices[idx + 4] = v;
        vertices[idx + 5] = x2;
        vertices[idx + 6] = y2;
        vertices[idx + 7] = color;
        vertices[idx + 8] = u;
        vertices[idx + 9] = v2;
        vertices[idx + 10] = x3;
        vertices[idx + 11] = y3;
        vertices[idx + 12] = color;
        vertices[idx + 13] = u2;
        vertices[idx + 14] = v2;
        vertices[idx + 15] = x4;
        vertices[idx + 16] = y4;
        vertices[idx + 17] = color;
        vertices[idx + 18] = u2;
        vertices[idx + 19] = v;
        this.idx = idx + 20;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void flush() {
        int i = this.idx;
        if (i == 0) {
            return;
        }
        this.renderCalls++;
        this.totalRenderCalls++;
        int spritesInBatch = i / 20;
        if (spritesInBatch > this.maxSpritesInBatch) {
            this.maxSpritesInBatch = spritesInBatch;
        }
        int count = spritesInBatch * 6;
        this.lastTexture.bind();
        Mesh mesh = this.mesh;
        mesh.setVertices(this.vertices, 0, this.idx);
        mesh.getIndicesBuffer().position(0);
        mesh.getIndicesBuffer().limit(count);
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
        mesh.render(shaderProgram, 4, 0, count);
        this.idx = 0;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void disableBlending() {
        if (this.blendingDisabled) {
            return;
        }
        flush();
        this.blendingDisabled = true;
    }

    @Override // com.badlogic.gdx.graphics.g2d.Batch
    public void enableBlending() {
        if (this.blendingDisabled) {
            flush();
            this.blendingDisabled = false;
        }
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

    /* JADX INFO: Access modifiers changed from: protected */
    public void switchTexture(Texture texture) {
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