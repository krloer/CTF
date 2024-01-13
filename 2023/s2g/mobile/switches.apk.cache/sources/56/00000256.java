package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public class ArrowShapeBuilder extends BaseShapeBuilder {
    public static void build(MeshPartBuilder builder, float x1, float y1, float z1, float x2, float y2, float z2, float capLength, float stemThickness, int divisions) {
        Vector3 begin = obtainV3().set(x1, y1, z1);
        Vector3 end = obtainV3().set(x2, y2, z2);
        float length = begin.dst(end);
        float coneHeight = length * capLength;
        double d = coneHeight;
        double sqrt = Math.sqrt(0.3333333432674408d);
        Double.isNaN(d);
        float coneDiameter = ((float) (d * sqrt)) * 2.0f;
        float stemLength = length - coneHeight;
        float stemDiameter = coneDiameter * stemThickness;
        Vector3 up = obtainV3().set(end).sub(begin).nor();
        Vector3 forward = obtainV3().set(up).crs(Vector3.Z);
        if (forward.isZero()) {
            forward.set(Vector3.X);
        }
        forward.crs(up).nor();
        Vector3 left = obtainV3().set(up).crs(forward).nor();
        Vector3 direction = obtainV3().set(end).sub(begin).nor();
        Matrix4 userTransform = builder.getVertexTransform(obtainM4());
        Matrix4 transform = obtainM4();
        float[] val = transform.val;
        val[0] = left.x;
        val[4] = up.x;
        val[8] = forward.x;
        val[1] = left.y;
        val[5] = up.y;
        val[9] = forward.y;
        val[2] = left.z;
        val[6] = up.z;
        val[10] = forward.z;
        Matrix4 temp = obtainM4();
        transform.setTranslation(obtainV3().set(direction).scl(stemLength / 2.0f).add(x1, y1, z1));
        builder.setVertexTransform(temp.set(transform).mul(userTransform));
        CylinderShapeBuilder.build(builder, stemDiameter, stemLength, stemDiameter, divisions);
        transform.setTranslation(obtainV3().set(direction).scl(stemLength).add(x1, y1, z1));
        builder.setVertexTransform(temp.set(transform).mul(userTransform));
        ConeShapeBuilder.build(builder, coneDiameter, coneHeight, coneDiameter, divisions);
        builder.setVertexTransform(userTransform);
        freeAll();
    }
}