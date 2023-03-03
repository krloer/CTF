package com.badlogic.gdx.math;

/* loaded from: classes.dex */
public final class WindowedMean {
    int last_value;
    float[] values;
    int added_values = 0;
    float mean = 0.0f;
    boolean dirty = true;

    public WindowedMean(int window_size) {
        this.values = new float[window_size];
    }

    public boolean hasEnoughData() {
        return this.added_values >= this.values.length;
    }

    public void clear() {
        this.added_values = 0;
        this.last_value = 0;
        int i = 0;
        while (true) {
            float[] fArr = this.values;
            if (i < fArr.length) {
                fArr[i] = 0.0f;
                i++;
            } else {
                this.dirty = true;
                return;
            }
        }
    }

    public void addValue(float value) {
        int i = this.added_values;
        if (i < this.values.length) {
            this.added_values = i + 1;
        }
        float[] fArr = this.values;
        int i2 = this.last_value;
        this.last_value = i2 + 1;
        fArr[i2] = value;
        if (this.last_value > fArr.length - 1) {
            this.last_value = 0;
        }
        this.dirty = true;
    }

    public float getMean() {
        float[] fArr;
        if (hasEnoughData()) {
            if (this.dirty) {
                float mean = 0.0f;
                int i = 0;
                while (true) {
                    fArr = this.values;
                    if (i >= fArr.length) {
                        break;
                    }
                    mean += fArr[i];
                    i++;
                }
                int i2 = fArr.length;
                this.mean = mean / i2;
                this.dirty = false;
            }
            float mean2 = this.mean;
            return mean2;
        }
        return 0.0f;
    }

    public float getOldest() {
        int i = this.added_values;
        float[] fArr = this.values;
        return i < fArr.length ? fArr[0] : fArr[this.last_value];
    }

    public float getLatest() {
        float[] fArr = this.values;
        int i = this.last_value;
        if (i - 1 == -1) {
            i = fArr.length;
        }
        return fArr[i - 1];
    }

    public float standardDeviation() {
        if (!hasEnoughData()) {
            return 0.0f;
        }
        float mean = getMean();
        float sum = 0.0f;
        int i = 0;
        while (true) {
            float[] fArr = this.values;
            if (i < fArr.length) {
                sum += (fArr[i] - mean) * (fArr[i] - mean);
                i++;
            } else {
                int i2 = fArr.length;
                return (float) Math.sqrt(sum / i2);
            }
        }
    }

    public float getLowest() {
        float lowest = Float.MAX_VALUE;
        int i = 0;
        while (true) {
            float[] fArr = this.values;
            if (i < fArr.length) {
                lowest = Math.min(lowest, fArr[i]);
                i++;
            } else {
                return lowest;
            }
        }
    }

    public float getHighest() {
        float lowest = Float.MIN_NORMAL;
        int i = 0;
        while (true) {
            float[] fArr = this.values;
            if (i < fArr.length) {
                lowest = Math.max(lowest, fArr[i]);
                i++;
            } else {
                return lowest;
            }
        }
    }

    public int getValueCount() {
        return this.added_values;
    }

    public int getWindowSize() {
        return this.values.length;
    }

    public float[] getWindowValues() {
        float[] windowValues = new float[this.added_values];
        if (hasEnoughData()) {
            for (int i = 0; i < windowValues.length; i++) {
                float[] fArr = this.values;
                windowValues[i] = fArr[(this.last_value + i) % fArr.length];
            }
        } else {
            System.arraycopy(this.values, 0, windowValues, 0, this.added_values);
        }
        return windowValues;
    }
}