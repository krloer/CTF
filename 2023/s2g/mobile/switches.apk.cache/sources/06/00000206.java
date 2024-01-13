package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public final class PointSpawnShapeValue extends PrimitiveSpawnShapeValue {
    public PointSpawnShapeValue(PointSpawnShapeValue value) {
        super(value);
        load(value);
    }

    public PointSpawnShapeValue() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public void spawnAux(Vector3 vector, float percent) {
        vector.x = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
        vector.y = this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent));
        vector.z = this.spawnDepth + (this.spawnDepthDiff * this.spawnDepthValue.getScale(percent));
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public SpawnShapeValue copy() {
        return new PointSpawnShapeValue(this);
    }
}