package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class FloatCounter implements Pool.Poolable {
    public float average;
    public int count;
    public float latest;
    public float max;
    public final WindowedMean mean;
    public float min;
    public float total;
    public float value;

    public FloatCounter(int windowSize) {
        this.mean = windowSize > 1 ? new WindowedMean(windowSize) : null;
        reset();
    }

    public void put(float value) {
        this.latest = value;
        this.total += value;
        this.count++;
        this.average = this.total / this.count;
        WindowedMean windowedMean = this.mean;
        if (windowedMean != null) {
            windowedMean.addValue(value);
            this.value = this.mean.getMean();
        } else {
            this.value = this.latest;
        }
        WindowedMean windowedMean2 = this.mean;
        if (windowedMean2 == null || windowedMean2.hasEnoughData()) {
            float f = this.value;
            if (f < this.min) {
                this.min = f;
            }
            float f2 = this.value;
            if (f2 > this.max) {
                this.max = f2;
            }
        }
    }

    @Override // com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        this.count = 0;
        this.total = 0.0f;
        this.min = Float.MAX_VALUE;
        this.max = -3.4028235E38f;
        this.average = 0.0f;
        this.latest = 0.0f;
        this.value = 0.0f;
        WindowedMean windowedMean = this.mean;
        if (windowedMean != null) {
            windowedMean.clear();
        }
    }

    public String toString() {
        return "FloatCounter{count=" + this.count + ", total=" + this.total + ", min=" + this.min + ", max=" + this.max + ", average=" + this.average + ", latest=" + this.latest + ", value=" + this.value + '}';
    }
}