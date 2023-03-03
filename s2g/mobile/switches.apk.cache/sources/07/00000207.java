package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public abstract class PrimitiveSpawnShapeValue extends SpawnShapeValue {
    protected static final Vector3 TMP_V1 = new Vector3();
    boolean edges;
    protected float spawnDepth;
    protected float spawnDepthDiff;
    public ScaledNumericValue spawnDepthValue;
    protected float spawnHeight;
    protected float spawnHeightDiff;
    public ScaledNumericValue spawnHeightValue;
    protected float spawnWidth;
    protected float spawnWidthDiff;
    public ScaledNumericValue spawnWidthValue;

    /* loaded from: classes.dex */
    public enum SpawnSide {
        both,
        top,
        bottom
    }

    public PrimitiveSpawnShapeValue() {
        this.edges = false;
        this.spawnWidthValue = new ScaledNumericValue();
        this.spawnHeightValue = new ScaledNumericValue();
        this.spawnDepthValue = new ScaledNumericValue();
    }

    public PrimitiveSpawnShapeValue(PrimitiveSpawnShapeValue value) {
        super(value);
        this.edges = false;
        this.spawnWidthValue = new ScaledNumericValue();
        this.spawnHeightValue = new ScaledNumericValue();
        this.spawnDepthValue = new ScaledNumericValue();
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue
    public void setActive(boolean active) {
        super.setActive(active);
        this.spawnWidthValue.setActive(true);
        this.spawnHeightValue.setActive(true);
        this.spawnDepthValue.setActive(true);
    }

    public boolean isEdges() {
        return this.edges;
    }

    public void setEdges(boolean edges) {
        this.edges = edges;
    }

    public ScaledNumericValue getSpawnWidth() {
        return this.spawnWidthValue;
    }

    public ScaledNumericValue getSpawnHeight() {
        return this.spawnHeightValue;
    }

    public ScaledNumericValue getSpawnDepth() {
        return this.spawnDepthValue;
    }

    public void setDimensions(float width, float height, float depth) {
        this.spawnWidthValue.setHigh(width);
        this.spawnHeightValue.setHigh(height);
        this.spawnDepthValue.setHigh(depth);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public void start() {
        this.spawnWidth = this.spawnWidthValue.newLowValue();
        this.spawnWidthDiff = this.spawnWidthValue.newHighValue();
        if (!this.spawnWidthValue.isRelative()) {
            this.spawnWidthDiff -= this.spawnWidth;
        }
        this.spawnHeight = this.spawnHeightValue.newLowValue();
        this.spawnHeightDiff = this.spawnHeightValue.newHighValue();
        if (!this.spawnHeightValue.isRelative()) {
            this.spawnHeightDiff -= this.spawnHeight;
        }
        this.spawnDepth = this.spawnDepthValue.newLowValue();
        this.spawnDepthDiff = this.spawnDepthValue.newHighValue();
        if (!this.spawnDepthValue.isRelative()) {
            this.spawnDepthDiff -= this.spawnDepth;
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue
    public void load(ParticleValue value) {
        super.load(value);
        PrimitiveSpawnShapeValue shape = (PrimitiveSpawnShapeValue) value;
        this.edges = shape.edges;
        this.spawnWidthValue.load(shape.spawnWidthValue);
        this.spawnHeightValue.load(shape.spawnHeightValue);
        this.spawnDepthValue.load(shape.spawnDepthValue);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("spawnWidthValue", this.spawnWidthValue);
        json.writeValue("spawnHeightValue", this.spawnHeightValue);
        json.writeValue("spawnDepthValue", this.spawnDepthValue);
        json.writeValue("edges", Boolean.valueOf(this.edges));
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.spawnWidthValue = (ScaledNumericValue) json.readValue("spawnWidthValue", ScaledNumericValue.class, jsonData);
        this.spawnHeightValue = (ScaledNumericValue) json.readValue("spawnHeightValue", ScaledNumericValue.class, jsonData);
        this.spawnDepthValue = (ScaledNumericValue) json.readValue("spawnDepthValue", ScaledNumericValue.class, jsonData);
        this.edges = ((Boolean) json.readValue("edges", Boolean.TYPE, jsonData)).booleanValue();
    }
}