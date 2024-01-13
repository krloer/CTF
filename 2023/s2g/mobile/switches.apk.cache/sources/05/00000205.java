package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public class ParticleValue implements Json.Serializable {
    public boolean active;

    public ParticleValue() {
    }

    public ParticleValue(ParticleValue value) {
        this.active = value.active;
    }

    public boolean isActive() {
        return this.active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public void load(ParticleValue value) {
        this.active = value.active;
    }

    @Override // com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        json.writeValue("active", Boolean.valueOf(this.active));
    }

    @Override // com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        this.active = ((Boolean) json.readValue("active", Boolean.class, jsonData)).booleanValue();
    }
}