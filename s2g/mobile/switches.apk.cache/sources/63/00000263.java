package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Matrix3;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.ShortArray;

/* loaded from: classes.dex */
public class SphereShapeBuilder extends BaseShapeBuilder {
    private static final ShortArray tmpIndices = new ShortArray();
    private static final Matrix3 normalTransform = new Matrix3();

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisionsU, int divisionsV) {
        build(builder, width, height, depth, divisionsU, divisionsV, 0.0f, 360.0f, 0.0f, 180.0f);
    }

    @Deprecated
    public static void build(MeshPartBuilder builder, Matrix4 transform, float width, float height, float depth, int divisionsU, int divisionsV) {
        build(builder, transform, width, height, depth, divisionsU, divisionsV, 0.0f, 360.0f, 0.0f, 180.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisionsU, int divisionsV, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        build(builder, matTmp1.idt(), width, height, depth, divisionsU, divisionsV, angleUFrom, angleUTo, angleVFrom, angleVTo);
    }

    @Deprecated
    public static void build(MeshPartBuilder builder, Matrix4 transform, float width, float height, float depth, int divisionsU, int divisionsV, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        float u;
        float v;
        float u2;
        MeshPartBuilder.VertexInfo curr1;
        int i = divisionsU;
        int i2 = divisionsV;
        boolean closedVFrom = MathUtils.isEqual(angleVFrom, 0.0f);
        boolean closedVTo = MathUtils.isEqual(angleVTo, 180.0f);
        float hw = width * 0.5f;
        float hh = height * 0.5f;
        float hd = depth * 0.5f;
        float auo = angleUFrom * 0.017453292f;
        float stepU = ((angleUTo - angleUFrom) * 0.017453292f) / i;
        float avo = angleVFrom * 0.017453292f;
        float stepV = ((angleVTo - angleVFrom) * 0.017453292f) / i2;
        float us = 1.0f / i;
        float vs = 1.0f / i2;
        MeshPartBuilder.VertexInfo curr12 = vertTmp3.set(null, null, null, null);
        curr12.hasNormal = true;
        curr12.hasPosition = true;
        curr12.hasUV = true;
        normalTransform.set(transform);
        int s = i + 3;
        tmpIndices.clear();
        tmpIndices.ensureCapacity(i * 2);
        tmpIndices.size = s;
        int tempOffset = 0;
        builder.ensureVertices((i2 + 1) * (i + 1));
        builder.ensureRectangleIndices(i);
        int iv = 0;
        while (iv <= i2) {
            int tempOffset2 = tempOffset;
            float angleV = avo + (iv * stepV);
            float v2 = iv * vs;
            float t = MathUtils.sin(angleV);
            float vs2 = vs;
            float vs3 = MathUtils.cos(angleV) * hh;
            float hh2 = hh;
            int iu = 0;
            float avo2 = avo;
            int tempOffset3 = tempOffset2;
            while (iu <= i) {
                float angleU = auo + (iu * stepU);
                if ((iv == 0 && closedVFrom) || (iv == i2 && closedVTo)) {
                    u = 1.0f - ((iu - 0.5f) * us);
                } else {
                    u = 1.0f - (iu * us);
                }
                float us2 = us;
                Vector3 vector3 = curr12.position;
                float hw2 = hw;
                float hw3 = MathUtils.cos(angleU) * hw * t;
                float auo2 = auo;
                float auo3 = MathUtils.sin(angleU) * hd * t;
                vector3.set(hw3, vs3, auo3);
                curr12.normal.set(curr12.position).mul(normalTransform).nor();
                curr12.position.mul(transform);
                curr12.uv.set(u, v2);
                tmpIndices.set(tempOffset3, builder.vertex(curr12));
                int o = tempOffset3 + s;
                if (iv <= 0 || iu <= 0) {
                    v = v2;
                    u2 = u;
                    curr1 = curr12;
                } else if (iv != 1 || !closedVFrom) {
                    v = v2;
                    u2 = u;
                    curr1 = curr12;
                    if (iv == i2 && closedVTo) {
                        builder.triangle(tmpIndices.get(tempOffset3), tmpIndices.get((o - (divisionsU + 2)) % s), tmpIndices.get((o - (divisionsU + 1)) % s));
                    } else {
                        builder.rect(tmpIndices.get(tempOffset3), tmpIndices.get((o - 1) % s), tmpIndices.get((o - (divisionsU + 2)) % s), tmpIndices.get((o - (divisionsU + 1)) % s));
                    }
                } else {
                    v = v2;
                    u2 = u;
                    curr1 = curr12;
                    builder.triangle(tmpIndices.get(tempOffset3), tmpIndices.get((o - 1) % s), tmpIndices.get((o - (divisionsU + 1)) % s));
                }
                tempOffset3 = (tempOffset3 + 1) % tmpIndices.size;
                iu++;
                i = divisionsU;
                i2 = divisionsV;
                us = us2;
                hw = hw2;
                auo = auo2;
                v2 = v;
                curr12 = curr1;
            }
            iv++;
            i = divisionsU;
            i2 = divisionsV;
            tempOffset = tempOffset3;
            avo = avo2;
            vs = vs2;
            hh = hh2;
            us = us;
        }
    }
}