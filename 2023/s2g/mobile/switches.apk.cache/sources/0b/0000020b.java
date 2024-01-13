package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public class ScaledNumericValue extends RangedNumericValue {
    private float highMax;
    private float highMin;
    private float[] scaling = {1.0f};
    public float[] timeline = {0.0f};
    private boolean relative = false;

    public float newHighValue() {
        float f = this.highMin;
        return f + ((this.highMax - f) * MathUtils.random());
    }

    public void setHigh(float value) {
        this.highMin = value;
        this.highMax = value;
    }

    public void setHigh(float min, float max) {
        this.highMin = min;
        this.highMax = max;
    }

    public float getHighMin() {
        return this.highMin;
    }

    public void setHighMin(float highMin) {
        this.highMin = highMin;
    }

    public float getHighMax() {
        return this.highMax;
    }

    public void setHighMax(float highMax) {
        this.highMax = highMax;
    }

    public float[] getScaling() {
        return this.scaling;
    }

    public void setScaling(float[] values) {
        this.scaling = values;
    }

    public float[] getTimeline() {
        return this.timeline;
    }

    public void setTimeline(float[] timeline) {
        this.timeline = timeline;
    }

    public boolean isRelative() {
        return this.relative;
    }

    public void setRelative(boolean relative) {
        this.relative = relative;
    }

    public float getScale(float percent) {
        int endIndex = -1;
        int n = this.timeline.length;
        int i = 1;
        while (true) {
            if (i >= n) {
                break;
            }
            float t = this.timeline[i];
            if (t <= percent) {
                i++;
            } else {
                endIndex = i;
                break;
            }
        }
        if (endIndex == -1) {
            return this.scaling[n - 1];
        }
        int startIndex = endIndex - 1;
        float[] fArr = this.scaling;
        float startValue = fArr[startIndex];
        float[] fArr2 = this.timeline;
        float startTime = fArr2[startIndex];
        return ((fArr[endIndex] - startValue) * ((percent - startTime) / (fArr2[endIndex] - startTime))) + startValue;
    }

    public void load(ScaledNumericValue value) {
        super.load((RangedNumericValue) value);
        this.highMax = value.highMax;
        this.highMin = value.highMin;
        this.scaling = new float[value.scaling.length];
        float[] fArr = value.scaling;
        float[] fArr2 = this.scaling;
        System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
        this.timeline = new float[value.timeline.length];
        float[] fArr3 = value.timeline;
        float[] fArr4 = this.timeline;
        System.arraycopy(fArr3, 0, fArr4, 0, fArr4.length);
        this.relative = value.relative;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.RangedNumericValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("highMin", Float.valueOf(this.highMin));
        json.writeValue("highMax", Float.valueOf(this.highMax));
        json.writeValue("relative", Boolean.valueOf(this.relative));
        json.writeValue("scaling", this.scaling);
        json.writeValue("timeline", this.timeline);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.RangedNumericValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.highMin = ((Float) json.readValue("highMin", Float.TYPE, jsonData)).floatValue();
        this.highMax = ((Float) json.readValue("highMax", Float.TYPE, jsonData)).floatValue();
        this.relative = ((Boolean) json.readValue("relative", Boolean.TYPE, jsonData)).booleanValue();
        this.scaling = (float[]) json.readValue("scaling", float[].class, jsonData);
        this.timeline = (float[]) json.readValue("timeline", float[].class, jsonData);
    }
}