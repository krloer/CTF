package com.badlogic.gdx.math;

import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class CumulativeDistribution<T> {
    private Array<CumulativeDistribution<T>.CumulativeValue> values = new Array<>(false, 10, CumulativeValue.class);

    /* loaded from: classes.dex */
    public class CumulativeValue {
        public float frequency;
        public float interval;
        public T value;

        public CumulativeValue(T value, float frequency, float interval) {
            this.value = value;
            this.frequency = frequency;
            this.interval = interval;
        }
    }

    public void add(T value, float intervalSize) {
        this.values.add(new CumulativeValue(value, 0.0f, intervalSize));
    }

    public void add(T value) {
        this.values.add(new CumulativeValue(value, 0.0f, 0.0f));
    }

    public void generate() {
        float sum = 0.0f;
        for (int i = 0; i < this.values.size; i++) {
            sum += this.values.items[i].interval;
            this.values.items[i].frequency = sum;
        }
    }

    public void generateNormalized() {
        float sum = 0.0f;
        for (int i = 0; i < this.values.size; i++) {
            sum += this.values.items[i].interval;
        }
        float intervalSum = 0.0f;
        for (int i2 = 0; i2 < this.values.size; i2++) {
            intervalSum += this.values.items[i2].interval / sum;
            this.values.items[i2].frequency = intervalSum;
        }
    }

    public void generateUniform() {
        float freq = 1.0f / this.values.size;
        for (int i = 0; i < this.values.size; i++) {
            this.values.items[i].interval = freq;
            this.values.items[i].frequency = (i + 1) * freq;
        }
    }

    public T value(float probability) {
        int imax = this.values.size - 1;
        int imin = 0;
        while (imin <= imax) {
            int imid = ((imax - imin) / 2) + imin;
            CumulativeDistribution<T>.CumulativeValue value = this.values.items[imid];
            if (probability < value.frequency) {
                imax = imid - 1;
            } else if (probability <= value.frequency) {
                break;
            } else {
                imin = imid + 1;
            }
        }
        return this.values.items[imin].value;
    }

    public T value() {
        return value(MathUtils.random());
    }

    public int size() {
        return this.values.size;
    }

    public float getInterval(int index) {
        return this.values.items[index].interval;
    }

    public T getValue(int index) {
        return this.values.items[index].value;
    }

    public void setInterval(T obj, float intervalSize) {
        Array.ArrayIterator<CumulativeDistribution<T>.CumulativeValue> it = this.values.iterator();
        while (it.hasNext()) {
            CumulativeDistribution<T>.CumulativeValue value = it.next();
            if (value.value == obj) {
                value.interval = intervalSize;
                return;
            }
        }
    }

    public void setInterval(int index, float intervalSize) {
        this.values.items[index].interval = intervalSize;
    }

    public void clear() {
        this.values.clear();
    }
}