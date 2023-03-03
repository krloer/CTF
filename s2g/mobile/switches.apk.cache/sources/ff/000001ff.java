package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.graphics.g3d.particles.values.PrimitiveSpawnShapeValue;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public final class EllipseSpawnShapeValue extends PrimitiveSpawnShapeValue {
    PrimitiveSpawnShapeValue.SpawnSide side;

    public EllipseSpawnShapeValue(EllipseSpawnShapeValue value) {
        super(value);
        this.side = PrimitiveSpawnShapeValue.SpawnSide.both;
        load(value);
    }

    public EllipseSpawnShapeValue() {
        this.side = PrimitiveSpawnShapeValue.SpawnSide.both;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public void spawnAux(Vector3 vector, float percent) {
        float radiusX;
        float radiusY;
        float radiusZ;
        float width = this.spawnWidth + (this.spawnWidthDiff * this.spawnWidthValue.getScale(percent));
        float height = this.spawnHeight + (this.spawnHeightDiff * this.spawnHeightValue.getScale(percent));
        float depth = this.spawnDepth + (this.spawnDepthDiff * this.spawnDepthValue.getScale(percent));
        float maxT = 6.2831855f;
        if (this.side == PrimitiveSpawnShapeValue.SpawnSide.top) {
            maxT = 3.1415927f;
        } else if (this.side == PrimitiveSpawnShapeValue.SpawnSide.bottom) {
            maxT = -3.1415927f;
        }
        float t = MathUtils.random(0.0f, maxT);
        if (this.edges) {
            if (width == 0.0f) {
                vector.set(0.0f, (height / 2.0f) * MathUtils.sin(t), (depth / 2.0f) * MathUtils.cos(t));
                return;
            } else if (height == 0.0f) {
                vector.set((width / 2.0f) * MathUtils.cos(t), 0.0f, (depth / 2.0f) * MathUtils.sin(t));
                return;
            } else if (depth == 0.0f) {
                vector.set((width / 2.0f) * MathUtils.cos(t), (height / 2.0f) * MathUtils.sin(t), 0.0f);
                return;
            } else {
                radiusX = width / 2.0f;
                radiusY = height / 2.0f;
                radiusZ = depth / 2.0f;
            }
        } else {
            float radiusX2 = width / 2.0f;
            radiusX = MathUtils.random(radiusX2);
            radiusY = MathUtils.random(height / 2.0f);
            radiusZ = MathUtils.random(depth / 2.0f);
        }
        float z = MathUtils.random(-1.0f, 1.0f);
        float r = (float) Math.sqrt(1.0f - (z * z));
        vector.set(radiusX * r * MathUtils.cos(t), radiusY * r * MathUtils.sin(t), radiusZ * z);
    }

    public PrimitiveSpawnShapeValue.SpawnSide getSide() {
        return this.side;
    }

    public void setSide(PrimitiveSpawnShapeValue.SpawnSide side) {
        this.side = side;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.PrimitiveSpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue
    public void load(ParticleValue value) {
        super.load(value);
        EllipseSpawnShapeValue shape = (EllipseSpawnShapeValue) value;
        this.side = shape.side;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public SpawnShapeValue copy() {
        return new EllipseSpawnShapeValue(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.PrimitiveSpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("side", this.side);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.PrimitiveSpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.side = (PrimitiveSpawnShapeValue.SpawnSide) json.readValue("side", PrimitiveSpawnShapeValue.SpawnSide.class, jsonData);
    }
}