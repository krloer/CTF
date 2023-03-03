package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.graphics.g3d.model.MeshPart;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public interface MeshPartBuilder {
    void addMesh(Mesh mesh);

    void addMesh(Mesh mesh, int i, int i2);

    void addMesh(MeshPart meshPart);

    void addMesh(float[] fArr, short[] sArr);

    void addMesh(float[] fArr, short[] sArr, int i, int i2);

    @Deprecated
    void arrow(float f, float f2, float f3, float f4, float f5, float f6, float f7, float f8, int i);

    @Deprecated
    void box(float f, float f2, float f3);

    @Deprecated
    void box(float f, float f2, float f3, float f4, float f5, float f6);

    @Deprecated
    void box(VertexInfo vertexInfo, VertexInfo vertexInfo2, VertexInfo vertexInfo3, VertexInfo vertexInfo4, VertexInfo vertexInfo5, VertexInfo vertexInfo6, VertexInfo vertexInfo7, VertexInfo vertexInfo8);

    @Deprecated
    void box(Matrix4 matrix4);

    @Deprecated
    void box(Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34, Vector3 vector35, Vector3 vector36, Vector3 vector37, Vector3 vector38);

    @Deprecated
    void capsule(float f, float f2, int i);

    @Deprecated
    void circle(float f, int i, float f2, float f3, float f4, float f5, float f6, float f7);

    @Deprecated
    void circle(float f, int i, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9);

    @Deprecated
    void circle(float f, int i, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13);

    @Deprecated
    void circle(float f, int i, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15);

    @Deprecated
    void circle(float f, int i, Vector3 vector3, Vector3 vector32);

    @Deprecated
    void circle(float f, int i, Vector3 vector3, Vector3 vector32, float f2, float f3);

    @Deprecated
    void circle(float f, int i, Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34);

    @Deprecated
    void circle(float f, int i, Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34, float f2, float f3);

    @Deprecated
    void cone(float f, float f2, float f3, int i);

    @Deprecated
    void cone(float f, float f2, float f3, int i, float f4, float f5);

    @Deprecated
    void cylinder(float f, float f2, float f3, int i);

    @Deprecated
    void cylinder(float f, float f2, float f3, int i, float f4, float f5);

    @Deprecated
    void cylinder(float f, float f2, float f3, int i, float f4, float f5, boolean z);

    @Deprecated
    void ellipse(float f, float f2, float f3, float f4, int i, float f5, float f6, float f7, float f8, float f9, float f10);

    @Deprecated
    void ellipse(float f, float f2, float f3, float f4, int i, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12);

    @Deprecated
    void ellipse(float f, float f2, float f3, float f4, int i, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15, float f16, float f17, float f18);

    @Deprecated
    void ellipse(float f, float f2, float f3, float f4, int i, Vector3 vector3, Vector3 vector32);

    @Deprecated
    void ellipse(float f, float f2, int i, float f3, float f4, float f5, float f6, float f7, float f8);

    @Deprecated
    void ellipse(float f, float f2, int i, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10);

    @Deprecated
    void ellipse(float f, float f2, int i, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14);

    @Deprecated
    void ellipse(float f, float f2, int i, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15, float f16);

    @Deprecated
    void ellipse(float f, float f2, int i, Vector3 vector3, Vector3 vector32);

    @Deprecated
    void ellipse(float f, float f2, int i, Vector3 vector3, Vector3 vector32, float f3, float f4);

    @Deprecated
    void ellipse(float f, float f2, int i, Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34);

    @Deprecated
    void ellipse(float f, float f2, int i, Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34, float f3, float f4);

    void ensureCapacity(int i, int i2);

    void ensureIndices(int i);

    void ensureRectangleIndices(int i);

    void ensureTriangleIndices(int i);

    void ensureVertices(int i);

    VertexAttributes getAttributes();

    MeshPart getMeshPart();

    int getPrimitiveType();

    Matrix4 getVertexTransform(Matrix4 matrix4);

    void index(short s);

    void index(short s, short s2);

    void index(short s, short s2, short s3);

    void index(short s, short s2, short s3, short s4);

    void index(short s, short s2, short s3, short s4, short s5, short s6);

    void index(short s, short s2, short s3, short s4, short s5, short s6, short s7, short s8);

    boolean isVertexTransformationEnabled();

    short lastIndex();

    void line(float f, float f2, float f3, float f4, float f5, float f6);

    void line(VertexInfo vertexInfo, VertexInfo vertexInfo2);

    void line(Vector3 vector3, Color color, Vector3 vector32, Color color2);

    void line(Vector3 vector3, Vector3 vector32);

    void line(short s, short s2);

    @Deprecated
    void patch(float f, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15, int i, int i2);

    @Deprecated
    void patch(VertexInfo vertexInfo, VertexInfo vertexInfo2, VertexInfo vertexInfo3, VertexInfo vertexInfo4, int i, int i2);

    @Deprecated
    void patch(Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34, Vector3 vector35, int i, int i2);

    void rect(float f, float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15);

    void rect(VertexInfo vertexInfo, VertexInfo vertexInfo2, VertexInfo vertexInfo3, VertexInfo vertexInfo4);

    void rect(Vector3 vector3, Vector3 vector32, Vector3 vector33, Vector3 vector34, Vector3 vector35);

    void rect(short s, short s2, short s3, short s4);

    void setColor(float f, float f2, float f3, float f4);

    void setColor(Color color);

    void setUVRange(float f, float f2, float f3, float f4);

    void setUVRange(TextureRegion textureRegion);

    void setVertexTransform(Matrix4 matrix4);

    void setVertexTransformationEnabled(boolean z);

    @Deprecated
    void sphere(float f, float f2, float f3, int i, int i2);

    @Deprecated
    void sphere(float f, float f2, float f3, int i, int i2, float f4, float f5, float f6, float f7);

    @Deprecated
    void sphere(Matrix4 matrix4, float f, float f2, float f3, int i, int i2);

    @Deprecated
    void sphere(Matrix4 matrix4, float f, float f2, float f3, int i, int i2, float f4, float f5, float f6, float f7);

    void triangle(VertexInfo vertexInfo, VertexInfo vertexInfo2, VertexInfo vertexInfo3);

    void triangle(Vector3 vector3, Color color, Vector3 vector32, Color color2, Vector3 vector33, Color color3);

    void triangle(Vector3 vector3, Vector3 vector32, Vector3 vector33);

    void triangle(short s, short s2, short s3);

    short vertex(VertexInfo vertexInfo);

    short vertex(Vector3 vector3, Vector3 vector32, Color color, Vector2 vector2);

    short vertex(float... fArr);

    /* loaded from: classes.dex */
    public static class VertexInfo implements Pool.Poolable {
        public boolean hasColor;
        public boolean hasNormal;
        public boolean hasPosition;
        public boolean hasUV;
        public final Vector3 position = new Vector3();
        public final Vector3 normal = new Vector3(0.0f, 1.0f, 0.0f);
        public final Color color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        public final Vector2 uv = new Vector2();

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.position.set(0.0f, 0.0f, 0.0f);
            this.normal.set(0.0f, 1.0f, 0.0f);
            this.color.set(1.0f, 1.0f, 1.0f, 1.0f);
            this.uv.set(0.0f, 0.0f);
        }

        public VertexInfo set(Vector3 pos, Vector3 nor, Color col, Vector2 uv) {
            reset();
            this.hasPosition = pos != null;
            if (this.hasPosition) {
                this.position.set(pos);
            }
            this.hasNormal = nor != null;
            if (this.hasNormal) {
                this.normal.set(nor);
            }
            this.hasColor = col != null;
            if (this.hasColor) {
                this.color.set(col);
            }
            this.hasUV = uv != null;
            if (this.hasUV) {
                this.uv.set(uv);
            }
            return this;
        }

        public VertexInfo set(VertexInfo other) {
            if (other == null) {
                return set(null, null, null, null);
            }
            this.hasPosition = other.hasPosition;
            this.position.set(other.position);
            this.hasNormal = other.hasNormal;
            this.normal.set(other.normal);
            this.hasColor = other.hasColor;
            this.color.set(other.color);
            this.hasUV = other.hasUV;
            this.uv.set(other.uv);
            return this;
        }

        public VertexInfo setPos(float x, float y, float z) {
            this.position.set(x, y, z);
            this.hasPosition = true;
            return this;
        }

        public VertexInfo setPos(Vector3 pos) {
            this.hasPosition = pos != null;
            if (this.hasPosition) {
                this.position.set(pos);
            }
            return this;
        }

        public VertexInfo setNor(float x, float y, float z) {
            this.normal.set(x, y, z);
            this.hasNormal = true;
            return this;
        }

        public VertexInfo setNor(Vector3 nor) {
            this.hasNormal = nor != null;
            if (this.hasNormal) {
                this.normal.set(nor);
            }
            return this;
        }

        public VertexInfo setCol(float r, float g, float b, float a) {
            this.color.set(r, g, b, a);
            this.hasColor = true;
            return this;
        }

        public VertexInfo setCol(Color col) {
            this.hasColor = col != null;
            if (this.hasColor) {
                this.color.set(col);
            }
            return this;
        }

        public VertexInfo setUV(float u, float v) {
            this.uv.set(u, v);
            this.hasUV = true;
            return this;
        }

        public VertexInfo setUV(Vector2 uv) {
            this.hasUV = uv != null;
            if (this.hasUV) {
                this.uv.set(uv);
            }
            return this;
        }

        public VertexInfo lerp(VertexInfo target, float alpha) {
            if (this.hasPosition && target.hasPosition) {
                this.position.lerp(target.position, alpha);
            }
            if (this.hasNormal && target.hasNormal) {
                this.normal.lerp(target.normal, alpha);
            }
            if (this.hasColor && target.hasColor) {
                this.color.lerp(target.color, alpha);
            }
            if (this.hasUV && target.hasUV) {
                this.uv.lerp(target.uv, alpha);
            }
            return this;
        }
    }
}