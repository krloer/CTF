package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public final class RectangleSpawnShapeValue extends PrimitiveSpawnShapeValue {
    public RectangleSpawnShapeValue(RectangleSpawnShapeValue value) {
        super(value);
        load(value);
    }

    public RectangleSpawnShapeValue() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public void spawnAux(Vector3 vector, float percent) {
        float tz;
        float ty;
        float tx;
        float width = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
        float height = this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent));
        float depth = this.spawnDepth + (this.spawnDepthDiff * this.spawnDepthValue.getScale(percent));
        if (this.edges) {
            int a = MathUtils.random(-1, 1);
            if (a == -1) {
                tx = MathUtils.random(1) == 0 ? (-width) / 2.0f : width / 2.0f;
                if (tx == 0.0f) {
                    ty = MathUtils.random(1) == 0 ? (-height) / 2.0f : height / 2.0f;
                    tz = MathUtils.random(1) == 0 ? (-depth) / 2.0f : depth / 2.0f;
                } else {
                    ty = MathUtils.random(height) - (height / 2.0f);
                    tz = MathUtils.random(depth) - (depth / 2.0f);
                }
            } else if (a == 0) {
                float tz2 = MathUtils.random(1) == 0 ? (-depth) / 2.0f : depth / 2.0f;
                if (tz2 == 0.0f) {
                    ty = MathUtils.random(1) == 0 ? (-height) / 2.0f : height / 2.0f;
                    tz = tz2;
                    tx = MathUtils.random(1) == 0 ? (-width) / 2.0f : width / 2.0f;
                } else {
                    ty = MathUtils.random(height) - (height / 2.0f);
                    tz = tz2;
                    tx = MathUtils.random(width) - (width / 2.0f);
                }
            } else {
                float ty2 = MathUtils.random(1) == 0 ? (-height) / 2.0f : height / 2.0f;
                if (ty2 == 0.0f) {
                    float tx2 = MathUtils.random(1) == 0 ? (-width) / 2.0f : width / 2.0f;
                    tz = MathUtils.random(1) == 0 ? (-depth) / 2.0f : depth / 2.0f;
                    ty = ty2;
                    tx = tx2;
                } else {
                    float tx3 = MathUtils.random(width) - (width / 2.0f);
                    float tx4 = MathUtils.random(depth);
                    tz = tx4 - (depth / 2.0f);
                    ty = ty2;
                    tx = tx3;
                }
            }
            vector.x = tx;
            vector.y = ty;
            vector.z = tz;
            return;
        }
        vector.x = MathUtils.random(width) - (width / 2.0f);
        vector.y = MathUtils.random(height) - (height / 2.0f);
        vector.z = MathUtils.random(depth) - (depth / 2.0f);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public SpawnShapeValue copy() {
        return new RectangleSpawnShapeValue(this);
    }
}