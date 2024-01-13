package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.MathUtils;

/* loaded from: classes.dex */
public class ConeShapeBuilder extends BaseShapeBuilder {
    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions) {
        build(builder, width, height, depth, divisions, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions, float angleFrom, float angleTo) {
        build(builder, width, height, depth, divisions, angleFrom, angleTo, true);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions, float angleFrom, float angleTo, boolean close) {
        builder.ensureVertices(divisions + 2);
        builder.ensureTriangleIndices(divisions);
        float hw = width * 0.5f;
        float hh = height * 0.5f;
        float hd = depth * 0.5f;
        float ao = angleFrom * 0.017453292f;
        float step = ((angleTo - angleFrom) * 0.017453292f) / divisions;
        float us = 1.0f / divisions;
        MeshPartBuilder.VertexInfo curr1 = vertTmp3.set(null, null, null, null);
        curr1.hasNormal = true;
        curr1.hasPosition = true;
        curr1.hasUV = true;
        MeshPartBuilder.VertexInfo curr2 = vertTmp4.set(null, null, null, null).setPos(0.0f, hh, 0.0f).setNor(0.0f, 1.0f, 0.0f).setUV(0.5f, 0.0f);
        short base = builder.vertex(curr2);
        short i2 = 0;
        for (int i = 0; i <= divisions; i++) {
            float angle = ao + (i * step);
            float u = 1.0f - (i * us);
            curr1.position.set(MathUtils.cos(angle) * hw, 0.0f, MathUtils.sin(angle) * hd);
            curr1.normal.set(curr1.position).nor();
            curr1.position.y = -hh;
            curr1.uv.set(u, 1.0f);
            short i1 = builder.vertex(curr1);
            if (i != 0) {
                builder.triangle(base, i1, i2);
            }
            i2 = i1;
        }
        if (close) {
            EllipseShapeBuilder.build(builder, width, depth, 0.0f, 0.0f, divisions, 0.0f, -hh, 0.0f, 0.0f, -1.0f, 0.0f, -1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 180.0f - angleTo, 180.0f - angleFrom);
        }
    }
}