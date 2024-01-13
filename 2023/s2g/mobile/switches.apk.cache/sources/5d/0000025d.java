package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.MathUtils;

/* loaded from: classes.dex */
public class CylinderShapeBuilder extends BaseShapeBuilder {
    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions) {
        build(builder, width, height, depth, divisions, 0.0f, 360.0f);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions, float angleFrom, float angleTo) {
        build(builder, width, height, depth, divisions, angleFrom, angleTo, true);
    }

    public static void build(MeshPartBuilder builder, float width, float height, float depth, int divisions, float angleFrom, float angleTo, boolean close) {
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
        MeshPartBuilder.VertexInfo curr2 = vertTmp4.set(null, null, null, null);
        curr2.hasNormal = true;
        curr2.hasPosition = true;
        curr2.hasUV = true;
        builder.ensureVertices((divisions + 1) * 2);
        builder.ensureRectangleIndices(divisions);
        short i3 = 0;
        short i4 = 0;
        for (int i = 0; i <= divisions; i++) {
            float angle = ao + (i * step);
            float u = 1.0f - (i * us);
            curr1.position.set(MathUtils.cos(angle) * hw, 0.0f, MathUtils.sin(angle) * hd);
            curr1.normal.set(curr1.position).nor();
            curr1.position.y = -hh;
            curr1.uv.set(u, 1.0f);
            curr2.position.set(curr1.position);
            curr2.normal.set(curr1.normal);
            curr2.position.y = hh;
            curr2.uv.set(u, 0.0f);
            short i2 = builder.vertex(curr1);
            short i1 = builder.vertex(curr2);
            if (i != 0) {
                builder.rect(i3, i1, i2, i4);
            }
            i4 = i2;
            i3 = i1;
        }
        if (close) {
            EllipseShapeBuilder.build(builder, width, depth, 0.0f, 0.0f, divisions, 0.0f, hh, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, angleFrom, angleTo);
            EllipseShapeBuilder.build(builder, width, depth, 0.0f, 0.0f, divisions, 0.0f, -hh, 0.0f, 0.0f, -1.0f, 0.0f, -1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 180.0f - angleTo, 180.0f - angleFrom);
        }
    }
}