package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public abstract class SpawnShapeValue extends ParticleValue implements ResourceData.Configurable, Json.Serializable {
    public RangedNumericValue xOffsetValue;
    public RangedNumericValue yOffsetValue;
    public RangedNumericValue zOffsetValue;

    public abstract SpawnShapeValue copy();

    public abstract void spawnAux(Vector3 vector3, float f);

    public SpawnShapeValue() {
        this.xOffsetValue = new RangedNumericValue();
        this.yOffsetValue = new RangedNumericValue();
        this.zOffsetValue = new RangedNumericValue();
    }

    public SpawnShapeValue(SpawnShapeValue spawnShapeValue) {
        this();
    }

    public final Vector3 spawn(Vector3 vector, float percent) {
        spawnAux(vector, percent);
        if (this.xOffsetValue.active) {
            vector.x += this.xOffsetValue.newLowValue();
        }
        if (this.yOffsetValue.active) {
            vector.y += this.yOffsetValue.newLowValue();
        }
        if (this.zOffsetValue.active) {
            vector.z += this.zOffsetValue.newLowValue();
        }
        return vector;
    }

    public void init() {
    }

    public void start() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue
    public void load(ParticleValue value) {
        super.load(value);
        SpawnShapeValue shape = (SpawnShapeValue) value;
        this.xOffsetValue.load(shape.xOffsetValue);
        this.yOffsetValue.load(shape.yOffsetValue);
        this.zOffsetValue.load(shape.zOffsetValue);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("xOffsetValue", this.xOffsetValue);
        json.writeValue("yOffsetValue", this.yOffsetValue);
        json.writeValue("zOffsetValue", this.zOffsetValue);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.xOffsetValue = (RangedNumericValue) json.readValue("xOffsetValue", RangedNumericValue.class, jsonData);
        this.yOffsetValue = (RangedNumericValue) json.readValue("yOffsetValue", RangedNumericValue.class, jsonData);
        this.zOffsetValue = (RangedNumericValue) json.readValue("zOffsetValue", RangedNumericValue.class, jsonData);
    }

    public void save(AssetManager manager, ResourceData data) {
    }

    public void load(AssetManager manager, ResourceData data) {
    }
}