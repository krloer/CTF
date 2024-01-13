package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class EllipseShapeBuilder extends BaseShapeBuilder {
    public static void build(MeshPartBuilder builder, float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        build(builder, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, Vector3 center, Vector3 normal) {
        build(builder, radius, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal) {
        build(builder, radius, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, tangent.x, tangent.y, tangent.z, binormal.x, binormal.y, binormal.z);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ) {
        build(builder, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        build(builder, radius * 2.0f, radius * 2.0f, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, Vector3 center, Vector3 normal, float angleFrom, float angleTo) {
        build(builder, radius, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal, float angleFrom, float angleTo) {
        build(builder, radius, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, tangent.x, tangent.y, tangent.z, binormal.x, binormal.y, binormal.z, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        build(builder, radius * 2.0f, 2.0f * radius, 0.0f, 0.0f, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        build(builder, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, Vector3 center, Vector3 normal) {
        build(builder, width, height, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal) {
        build(builder, width, height, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, tangent.x, tangent.y, tangent.z, binormal.x, binormal.y, binormal.z);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ) {
        build(builder, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        build(builder, width, height, 0.0f, 0.0f, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, Vector3 center, Vector3 normal, float angleFrom, float angleTo) {
        build(builder, width, height, 0.0f, 0.0f, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal, float angleFrom, float angleTo) {
        build(builder, width, height, 0.0f, 0.0f, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, tangent.x, tangent.y, tangent.z, binormal.x, binormal.y, binormal.z, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        build(builder, width, height, 0.0f, 0.0f, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        tmpV1.set(normalX, normalY, normalZ).crs(0.0f, 0.0f, 1.0f);
        tmpV2.set(normalX, normalY, normalZ).crs(0.0f, 1.0f, 0.0f);
        if (tmpV2.len2() > tmpV1.len2()) {
            tmpV1.set(tmpV2);
        }
        tmpV2.set(tmpV1.nor()).crs(normalX, normalY, normalZ).nor();
        build(builder, width, height, innerWidth, innerHeight, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tmpV1.x, tmpV1.y, tmpV1.z, tmpV2.x, tmpV2.y, tmpV2.z, angleFrom, angleTo);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        build(builder, width, height, innerWidth, innerHeight, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float innerWidth, float innerHeight, int divisions, Vector3 center, Vector3 normal) {
        build(builder, width, height, innerWidth, innerHeight, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        short i3;
        short i4;
        Vector3 syIn;
        Vector3 syIn2;
        short i2;
        float f = centerX;
        if (innerWidth <= 0.0f || innerHeight <= 0.0f) {
            builder.ensureVertices(divisions + 2);
            builder.ensureTriangleIndices(divisions);
        } else if (innerWidth != width || innerHeight != height) {
            builder.ensureVertices((divisions + 1) * 2);
            builder.ensureRectangleIndices(divisions + 1);
        } else {
            builder.ensureVertices(divisions + 1);
            builder.ensureIndices(divisions + 1);
            if (builder.getPrimitiveType() != 1) {
                throw new GdxRuntimeException("Incorrect primitive type : expect GL_LINES because innerWidth == width && innerHeight == height");
            }
        }
        float ao = angleFrom * 0.017453292f;
        float step = ((angleTo - angleFrom) * 0.017453292f) / divisions;
        Vector3 sxEx = tmpV1.set(tangentX, tangentY, tangentZ).scl(width * 0.5f);
        Vector3 sxEx2 = sxEx;
        Vector3 syEx = tmpV2.set(binormalX, binormalY, binormalZ).scl(height * 0.5f);
        Vector3 sxIn = tmpV3.set(tangentX, tangentY, tangentZ).scl(innerWidth * 0.5f);
        Vector3 syIn3 = tmpV4.set(binormalX, binormalY, binormalZ).scl(innerHeight * 0.5f);
        MeshPartBuilder.VertexInfo currIn = vertTmp3.set(null, null, null, null);
        currIn.hasNormal = true;
        currIn.hasPosition = true;
        currIn.hasUV = true;
        currIn.uv.set(0.5f, 0.5f);
        currIn.position.set(f, centerY, centerZ);
        currIn.normal.set(normalX, normalY, normalZ);
        MeshPartBuilder.VertexInfo currEx = vertTmp4.set(null, null, null, null);
        currEx.hasNormal = true;
        currEx.hasPosition = true;
        currEx.hasUV = true;
        currEx.uv.set(0.5f, 0.5f);
        currEx.position.set(f, centerY, centerZ);
        currEx.normal.set(normalX, normalY, normalZ);
        short center = builder.vertex(currEx);
        float us = (innerWidth / width) * 0.5f;
        float vs = (innerHeight / height) * 0.5f;
        short i22 = 0;
        short i1 = 0;
        short i42 = 0;
        int i = 0;
        while (i <= divisions) {
            float angle = ao + (i * step);
            float x = MathUtils.cos(angle);
            float y = MathUtils.sin(angle);
            short center2 = center;
            Vector3 sxEx3 = sxEx2;
            short i32 = i1;
            short i43 = i42;
            Vector3 syIn4 = syIn3;
            currEx.position.set(f, centerY, centerZ).add((sxEx3.x * x) + (syEx.x * y), (sxEx3.y * x) + (syEx.y * y), (sxEx3.z * x) + (syEx.z * y));
            currEx.uv.set((x * 0.5f) + 0.5f, (y * 0.5f) + 0.5f);
            short i12 = builder.vertex(currEx);
            if (innerWidth > 0.0f) {
                if (innerHeight <= 0.0f) {
                    i3 = i32;
                    i4 = i43;
                    syIn = syIn4;
                    syIn2 = syEx;
                } else {
                    if (innerWidth == width && innerHeight == height) {
                        if (i != 0) {
                            builder.line(i12, i22);
                        }
                        i22 = i12;
                        i3 = i32;
                        i4 = i43;
                        syIn = syIn4;
                        syIn2 = syEx;
                        i2 = center2;
                    } else {
                        syIn = syIn4;
                        syIn2 = syEx;
                        currIn.position.set(f, centerY, centerZ).add((sxIn.x * x) + (syIn.x * y), (sxIn.y * x) + (syIn.y * y), (sxIn.z * x) + (syIn.z * y));
                        currIn.uv.set((us * x) + 0.5f, (vs * y) + 0.5f);
                        short i13 = builder.vertex(currIn);
                        if (i != 0) {
                            builder.rect(i13, i12, i43, i32);
                        }
                        i22 = i12;
                        i3 = i13;
                        i4 = i22;
                        i2 = center2;
                    }
                    i++;
                    center = i2;
                    i1 = i3;
                    i42 = i4;
                    syIn3 = syIn;
                    syEx = syIn2;
                    sxEx2 = sxEx3;
                    f = centerX;
                }
            } else {
                i3 = i32;
                i4 = i43;
                syIn = syIn4;
                syIn2 = syEx;
            }
            if (i != 0) {
                i2 = center2;
                builder.triangle(i12, i22, i2);
            } else {
                i2 = center2;
            }
            i22 = i12;
            i++;
            center = i2;
            i1 = i3;
            i42 = i4;
            syIn3 = syIn;
            syEx = syIn2;
            sxEx2 = sxEx3;
            f = centerX;
        }
    }
}