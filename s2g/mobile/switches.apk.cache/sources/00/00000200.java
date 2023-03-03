package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public class GradientColorValue extends ParticleValue {
    private static float[] temp = new float[3];
    private float[] colors = {1.0f, 1.0f, 1.0f};
    public float[] timeline = {0.0f};

    public float[] getTimeline() {
        return this.timeline;
    }

    public void setTimeline(float[] timeline) {
        this.timeline = timeline;
    }

    public float[] getColors() {
        return this.colors;
    }

    public void setColors(float[] colors) {
        this.colors = colors;
    }

    public float[] getColor(float percent) {
        getColor(percent, temp, 0);
        return temp;
    }

    public void getColor(float percent, float[] out, int index) {
        int startIndex = 0;
        int endIndex = -1;
        float[] timeline = this.timeline;
        int n = timeline.length;
        int i = 1;
        while (true) {
            if (i >= n) {
                break;
            }
            float t = timeline[i];
            if (t > percent) {
                endIndex = i;
                break;
            } else {
                startIndex = i;
                i++;
            }
        }
        float startTime = timeline[startIndex];
        int startIndex2 = startIndex * 3;
        float[] fArr = this.colors;
        float r1 = fArr[startIndex2];
        float g1 = fArr[startIndex2 + 1];
        float b1 = fArr[startIndex2 + 2];
        if (endIndex == -1) {
            out[index] = r1;
            out[index + 1] = g1;
            out[index + 2] = b1;
            return;
        }
        float factor = (percent - startTime) / (timeline[endIndex] - startTime);
        int endIndex2 = endIndex * 3;
        out[index] = ((fArr[endIndex2] - r1) * factor) + r1;
        out[index + 1] = ((fArr[endIndex2 + 1] - g1) * factor) + g1;
        out[index + 2] = ((fArr[endIndex2 + 2] - b1) * factor) + b1;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("colors", this.colors);
        json.writeValue("timeline", this.timeline);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.colors = (float[]) json.readValue("colors", float[].class, jsonData);
        this.timeline = (float[]) json.readValue("timeline", float[].class, jsonData);
    }

    public void load(GradientColorValue value) {
        super.load((ParticleValue) value);
        this.colors = new float[value.colors.length];
        float[] fArr = value.colors;
        float[] fArr2 = this.colors;
        System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
        this.timeline = new float[value.timeline.length];
        float[] fArr3 = value.timeline;
        float[] fArr4 = this.timeline;
        System.arraycopy(fArr3, 0, fArr4, 0, fArr4.length);
    }
}