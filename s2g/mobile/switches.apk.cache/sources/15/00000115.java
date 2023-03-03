package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.Affine2;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class CpuSpriteBatch extends SpriteBatch {
    private final Affine2 adjustAffine;
    private boolean adjustNeeded;
    private boolean haveIdentityRealMatrix;
    private final Affine2 tmpAffine;
    private final Matrix4 virtualMatrix;

    public CpuSpriteBatch() {
        this(1000);
    }

    public CpuSpriteBatch(int size) {
        this(size, null);
    }

    public CpuSpriteBatch(int size, ShaderProgram defaultShader) {
        super(size, defaultShader);
        this.virtualMatrix = new Matrix4();
        this.adjustAffine = new Affine2();
        this.haveIdentityRealMatrix = true;
        this.tmpAffine = new Affine2();
    }

    public void flushAndSyncTransformMatrix() {
        flush();
        if (this.adjustNeeded) {
            this.haveIdentityRealMatrix = checkIdt(this.virtualMatrix);
            if (!this.haveIdentityRealMatrix && this.virtualMatrix.det() == 0.0f) {
                throw new GdxRuntimeException("Transform matrix is singular, can't sync");
            }
            this.adjustNeeded = false;
            super.setTransformMatrix(this.virtualMatrix);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public Matrix4 getTransformMatrix() {
        return this.adjustNeeded ? this.virtualMatrix : super.getTransformMatrix();
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void setTransformMatrix(Matrix4 transform) {
        Matrix4 realMatrix = super.getTransformMatrix();
        if (checkEqual(realMatrix, transform)) {
            this.adjustNeeded = false;
        } else if (isDrawing()) {
            this.virtualMatrix.setAsAffine(transform);
            this.adjustNeeded = true;
            if (this.haveIdentityRealMatrix) {
                this.adjustAffine.set(transform);
                return;
            }
            this.tmpAffine.set(transform);
            this.adjustAffine.set(realMatrix).inv().mul(this.tmpAffine);
        } else {
            realMatrix.setAsAffine(transform);
            this.haveIdentityRealMatrix = checkIdt(realMatrix);
        }
    }

    public void setTransformMatrix(Affine2 transform) {
        Matrix4 realMatrix = super.getTransformMatrix();
        if (checkEqual(realMatrix, transform)) {
            this.adjustNeeded = false;
            return;
        }
        this.virtualMatrix.setAsAffine(transform);
        if (isDrawing()) {
            this.adjustNeeded = true;
            if (this.haveIdentityRealMatrix) {
                this.adjustAffine.set(transform);
                return;
            } else {
                this.adjustAffine.set(realMatrix).inv().mul(transform);
                return;
            }
        }
        realMatrix.setAsAffine(transform);
        this.haveIdentityRealMatrix = checkIdt(realMatrix);
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y, originX, originY, width, height, scaleX, scaleY, rotation, srcX, srcY, srcWidth, srcHeight, flipX, flipY);
        } else {
            drawAdjusted(texture, x, y, originX, originY, width, height, scaleX, scaleY, rotation, srcX, srcY, srcWidth, srcHeight, flipX, flipY);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y, width, height, srcX, srcY, srcWidth, srcHeight, flipX, flipY);
        } else {
            drawAdjusted(texture, x, y, 0.0f, 0.0f, width, height, 1.0f, 1.0f, 0.0f, srcX, srcY, srcWidth, srcHeight, flipX, flipY);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, int srcX, int srcY, int srcWidth, int srcHeight) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y, srcX, srcY, srcWidth, srcHeight);
        } else {
            drawAdjusted(texture, x, y, 0.0f, 0.0f, srcWidth, srcHeight, 1.0f, 1.0f, 0.0f, srcX, srcY, srcWidth, srcHeight, false, false);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height, float u, float v, float u2, float v2) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y, width, height, u, v, u2, v2);
        } else {
            drawAdjustedUV(texture, x, y, 0.0f, 0.0f, width, height, 1.0f, 1.0f, 0.0f, u, v, u2, v2, false, false);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y);
        } else {
            drawAdjusted(texture, x, y, 0.0f, 0.0f, texture.getWidth(), texture.getHeight(), 1.0f, 1.0f, 0.0f, 0, 1, 1, 0, false, false);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float x, float y, float width, float height) {
        if (!this.adjustNeeded) {
            super.draw(texture, x, y, width, height);
        } else {
            drawAdjusted(texture, x, y, 0.0f, 0.0f, width, height, 1.0f, 1.0f, 0.0f, 0, 1, 1, 0, false, false);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y) {
        if (!this.adjustNeeded) {
            super.draw(region, x, y);
        } else {
            drawAdjusted(region, x, y, 0.0f, 0.0f, region.getRegionWidth(), region.getRegionHeight(), 1.0f, 1.0f, 0.0f);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float width, float height) {
        if (!this.adjustNeeded) {
            super.draw(region, x, y, width, height);
        } else {
            drawAdjusted(region, x, y, 0.0f, 0.0f, width, height, 1.0f, 1.0f, 0.0f);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        if (!this.adjustNeeded) {
            super.draw(region, x, y, originX, originY, width, height, scaleX, scaleY, rotation);
        } else {
            drawAdjusted(region, x, y, originX, originY, width, height, scaleX, scaleY, rotation);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, boolean clockwise) {
        if (!this.adjustNeeded) {
            super.draw(region, x, y, originX, originY, width, height, scaleX, scaleY, rotation, clockwise);
        } else {
            drawAdjusted(region, x, y, originX, originY, width, height, scaleX, scaleY, rotation, clockwise);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(Texture texture, float[] spriteVertices, int offset, int count) {
        if (count % 20 != 0) {
            throw new GdxRuntimeException("invalid vertex count");
        }
        if (!this.adjustNeeded) {
            super.draw(texture, spriteVertices, offset, count);
        } else {
            drawAdjusted(texture, spriteVertices, offset, count);
        }
    }

    @Override // com.badlogic.gdx.graphics.g2d.SpriteBatch, com.badlogic.gdx.graphics.g2d.Batch
    public void draw(TextureRegion region, float width, float height, Affine2 transform) {
        if (!this.adjustNeeded) {
            super.draw(region, width, height, transform);
        } else {
            drawAdjusted(region, width, height, transform);
        }
    }

    private void drawAdjusted(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        drawAdjustedUV(region.texture, x, y, originX, originY, width, height, scaleX, scaleY, rotation, region.u, region.v2, region.u2, region.v, false, false);
    }

    private void drawAdjusted(Texture texture, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, int srcX, int srcY, int srcWidth, int srcHeight, boolean flipX, boolean flipY) {
        float invTexWidth = 1.0f / texture.getWidth();
        float invTexHeight = 1.0f / texture.getHeight();
        float u = srcX * invTexWidth;
        float v = (srcY + srcHeight) * invTexHeight;
        float u2 = (srcX + srcWidth) * invTexWidth;
        float v2 = srcY * invTexHeight;
        drawAdjustedUV(texture, x, y, originX, originY, width, height, scaleX, scaleY, rotation, u, v, u2, v2, flipX, flipY);
    }

    private void drawAdjustedUV(Texture texture, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, float u, float v, float u2, float v2, boolean flipX, boolean flipY) {
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        float x4;
        float cos;
        float u3;
        float u22;
        float v3;
        float v22;
        if (!this.drawing) {
            throw new IllegalStateException("CpuSpriteBatch.begin must be called before draw.");
        }
        if (texture == this.lastTexture) {
            if (this.idx == this.vertices.length) {
                super.flush();
            }
        } else {
            switchTexture(texture);
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
        if (!flipX) {
            u3 = u;
            u22 = u2;
        } else {
            u3 = u2;
            u22 = u;
        }
        if (!flipY) {
            v3 = v;
            v22 = v2;
        } else {
            v3 = v2;
            v22 = v;
        }
        Affine2 t = this.adjustAffine;
        this.vertices[this.idx + 0] = (t.m00 * x12) + (t.m01 * y12) + t.m02;
        this.vertices[this.idx + 1] = (t.m10 * x12) + (t.m11 * y12) + t.m12;
        this.vertices[this.idx + 2] = this.colorPacked;
        this.vertices[this.idx + 3] = u3;
        this.vertices[this.idx + 4] = v3;
        this.vertices[this.idx + 5] = (t.m00 * x22) + (t.m01 * y22) + t.m02;
        this.vertices[this.idx + 6] = (t.m10 * x22) + (t.m11 * y22) + t.m12;
        this.vertices[this.idx + 7] = this.colorPacked;
        this.vertices[this.idx + 8] = u3;
        this.vertices[this.idx + 9] = v22;
        this.vertices[this.idx + 10] = (t.m00 * x32) + (t.m01 * y32) + t.m02;
        this.vertices[this.idx + 11] = (t.m10 * x32) + (t.m11 * y32) + t.m12;
        this.vertices[this.idx + 12] = this.colorPacked;
        this.vertices[this.idx + 13] = u22;
        this.vertices[this.idx + 14] = v22;
        this.vertices[this.idx + 15] = (t.m00 * x42) + (t.m01 * y4) + t.m02;
        this.vertices[this.idx + 16] = (t.m10 * x42) + (t.m11 * y4) + t.m12;
        this.vertices[this.idx + 17] = this.colorPacked;
        this.vertices[this.idx + 18] = u22;
        this.vertices[this.idx + 19] = v3;
        this.idx += 20;
    }

    private void drawAdjusted(TextureRegion region, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation, boolean clockwise) {
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
        if (this.drawing) {
            if (region.texture != this.lastTexture) {
                switchTexture(region.texture);
            } else if (this.idx == this.vertices.length) {
                super.flush();
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
            Affine2 t = this.adjustAffine;
            this.vertices[this.idx + 0] = (t.m00 * x12) + (t.m01 * y12) + t.m02;
            this.vertices[this.idx + 1] = (t.m10 * x12) + (t.m11 * y12) + t.m12;
            this.vertices[this.idx + 2] = this.colorPacked;
            this.vertices[this.idx + 3] = u1;
            this.vertices[this.idx + 4] = v1;
            this.vertices[this.idx + 5] = (t.m00 * x22) + (t.m01 * y22) + t.m02;
            this.vertices[this.idx + 6] = (t.m10 * x22) + (t.m11 * y22) + t.m12;
            this.vertices[this.idx + 7] = this.colorPacked;
            this.vertices[this.idx + 8] = u2;
            this.vertices[this.idx + 9] = v2;
            this.vertices[this.idx + 10] = (t.m00 * x32) + (t.m01 * y32) + t.m02;
            this.vertices[this.idx + 11] = (t.m10 * x32) + (t.m11 * y32) + t.m12;
            this.vertices[this.idx + 12] = this.colorPacked;
            this.vertices[this.idx + 13] = u3;
            this.vertices[this.idx + 14] = v3;
            this.vertices[this.idx + 15] = (t.m00 * x42) + (t.m01 * y4) + t.m02;
            this.vertices[this.idx + 16] = (t.m10 * x42) + (t.m11 * y4) + t.m12;
            this.vertices[this.idx + 17] = this.colorPacked;
            this.vertices[this.idx + 18] = u4;
            this.vertices[this.idx + 19] = u42;
            this.idx += 20;
            return;
        }
        throw new IllegalStateException("CpuSpriteBatch.begin must be called before draw.");
    }

    private void drawAdjusted(TextureRegion region, float width, float height, Affine2 transform) {
        if (this.drawing) {
            if (region.texture != this.lastTexture) {
                switchTexture(region.texture);
            } else if (this.idx == this.vertices.length) {
                super.flush();
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
            Affine2 t = this.adjustAffine;
            this.vertices[this.idx + 0] = (t.m00 * x1) + (t.m01 * y1) + t.m02;
            this.vertices[this.idx + 1] = (t.m10 * x1) + (t.m11 * y1) + t.m12;
            this.vertices[this.idx + 2] = this.colorPacked;
            this.vertices[this.idx + 3] = u;
            this.vertices[this.idx + 4] = v;
            this.vertices[this.idx + 5] = (t.m00 * x2) + (t.m01 * y2) + t.m02;
            this.vertices[this.idx + 6] = (t.m10 * x2) + (t.m11 * y2) + t.m12;
            this.vertices[this.idx + 7] = this.colorPacked;
            this.vertices[this.idx + 8] = u;
            this.vertices[this.idx + 9] = v2;
            this.vertices[this.idx + 10] = (t.m00 * x3) + (t.m01 * y3) + t.m02;
            this.vertices[this.idx + 11] = (t.m10 * x3) + (t.m11 * y3) + t.m12;
            this.vertices[this.idx + 12] = this.colorPacked;
            this.vertices[this.idx + 13] = u2;
            this.vertices[this.idx + 14] = v2;
            this.vertices[this.idx + 15] = (t.m00 * x4) + (t.m01 * y4) + t.m02;
            this.vertices[this.idx + 16] = (t.m10 * x4) + (t.m11 * y4) + t.m12;
            this.vertices[this.idx + 17] = this.colorPacked;
            this.vertices[this.idx + 18] = u2;
            this.vertices[this.idx + 19] = v;
            this.idx += 20;
            return;
        }
        throw new IllegalStateException("CpuSpriteBatch.begin must be called before draw.");
    }

    private void drawAdjusted(Texture texture, float[] spriteVertices, int offset, int count) {
        if (!this.drawing) {
            throw new IllegalStateException("CpuSpriteBatch.begin must be called before draw.");
        }
        if (texture != this.lastTexture) {
            switchTexture(texture);
        }
        Affine2 t = this.adjustAffine;
        int copyCount = Math.min(this.vertices.length - this.idx, count);
        do {
            count -= copyCount;
            while (copyCount > 0) {
                float x = spriteVertices[offset];
                float y = spriteVertices[offset + 1];
                this.vertices[this.idx] = (t.m00 * x) + (t.m01 * y) + t.m02;
                this.vertices[this.idx + 1] = (t.m10 * x) + (t.m11 * y) + t.m12;
                this.vertices[this.idx + 2] = spriteVertices[offset + 2];
                this.vertices[this.idx + 3] = spriteVertices[offset + 3];
                this.vertices[this.idx + 4] = spriteVertices[offset + 4];
                this.idx += 5;
                offset += 5;
                copyCount -= 5;
            }
            if (count > 0) {
                super.flush();
                copyCount = Math.min(this.vertices.length, count);
                continue;
            }
        } while (count > 0);
    }

    private static boolean checkEqual(Matrix4 a, Matrix4 b) {
        if (a == b) {
            return true;
        }
        return a.val[0] == b.val[0] && a.val[1] == b.val[1] && a.val[4] == b.val[4] && a.val[5] == b.val[5] && a.val[12] == b.val[12] && a.val[13] == b.val[13];
    }

    private static boolean checkEqual(Matrix4 matrix, Affine2 affine) {
        float[] val = matrix.getValues();
        return val[0] == affine.m00 && val[1] == affine.m10 && val[4] == affine.m01 && val[5] == affine.m11 && val[12] == affine.m02 && val[13] == affine.m12;
    }

    private static boolean checkIdt(Matrix4 matrix) {
        float[] val = matrix.getValues();
        return val[0] == 1.0f && val[1] == 0.0f && val[4] == 0.0f && val[5] == 1.0f && val[12] == 0.0f && val[13] == 0.0f;
    }
}