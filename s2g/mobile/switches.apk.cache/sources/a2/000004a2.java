package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.Pool;
import java.util.Arrays;

/* loaded from: classes.dex */
public class QuadTreeFloat implements Pool.Poolable {
    public static final int DISTSQR = 3;
    public static final int VALUE = 0;
    public static final int X = 1;
    public static final int Y = 2;
    private static final Pool<QuadTreeFloat> pool = new Pool(128, 4096) { // from class: com.badlogic.gdx.utils.QuadTreeFloat.1
        @Override // com.badlogic.gdx.utils.Pool
        protected Object newObject() {
            return new QuadTreeFloat();
        }
    };
    public int count;
    public int depth;
    public float height;
    public final int maxDepth;
    public final int maxValues;
    public QuadTreeFloat ne;
    public QuadTreeFloat nw;
    public QuadTreeFloat se;
    public QuadTreeFloat sw;
    public float[] values;
    public float width;
    public float x;
    public float y;

    public QuadTreeFloat() {
        this(16, 8);
    }

    public QuadTreeFloat(int maxValues, int maxDepth) {
        this.maxValues = maxValues * 3;
        this.maxDepth = maxDepth;
        this.values = new float[this.maxValues];
    }

    public void setBounds(float x, float y, float width, float height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    public void add(float value, float valueX, float valueY) {
        int count = this.count;
        if (count == -1) {
            addToChild(value, valueX, valueY);
            return;
        }
        if (this.depth < this.maxDepth) {
            if (count == this.maxValues) {
                split(value, valueX, valueY);
                return;
            }
        } else {
            float[] fArr = this.values;
            if (count == fArr.length) {
                this.values = Arrays.copyOf(fArr, growValues());
            }
        }
        float[] fArr2 = this.values;
        fArr2[count] = value;
        fArr2[count + 1] = valueX;
        fArr2[count + 2] = valueY;
        this.count += 3;
    }

    private void split(float value, float valueX, float valueY) {
        float[] values = this.values;
        for (int i = 0; i < this.maxValues; i += 3) {
            addToChild(values[i], values[i + 1], values[i + 2]);
        }
        this.count = -1;
        addToChild(value, valueX, valueY);
    }

    private void addToChild(float value, float valueX, float valueY) {
        QuadTreeFloat child;
        float halfWidth = this.width / 2.0f;
        float halfHeight = this.height / 2.0f;
        float f = this.x;
        if (valueX < f + halfWidth) {
            float f2 = this.y;
            if (valueY < f2 + halfHeight) {
                child = this.sw;
                if (child == null) {
                    child = obtainChild(f, f2, halfWidth, halfHeight, this.depth + 1);
                    this.sw = child;
                }
            } else {
                child = this.nw;
                if (child == null) {
                    child = obtainChild(f, f2 + halfHeight, halfWidth, halfHeight, this.depth + 1);
                    this.nw = child;
                }
            }
        } else {
            float f3 = this.y;
            if (valueY < f3 + halfHeight) {
                child = this.se;
                if (child == null) {
                    child = obtainChild(f + halfWidth, f3, halfWidth, halfHeight, this.depth + 1);
                    this.se = child;
                }
            } else {
                child = this.ne;
                if (child == null) {
                    child = obtainChild(f + halfWidth, f3 + halfHeight, halfWidth, halfHeight, this.depth + 1);
                    this.ne = child;
                }
            }
        }
        child.add(value, valueX, valueY);
    }

    private QuadTreeFloat obtainChild(float x, float y, float width, float height, int depth) {
        QuadTreeFloat child = pool.obtain();
        child.x = x;
        child.y = y;
        child.width = width;
        child.height = height;
        child.depth = depth;
        return child;
    }

    protected int growValues() {
        return this.count + 30;
    }

    public void query(float centerX, float centerY, float radius, FloatArray results) {
        query(centerX, centerY, radius * radius, centerX - radius, centerY - radius, radius * 2.0f, results);
    }

    private void query(float centerX, float centerY, float radiusSqr, float rectX, float rectY, float rectSize, FloatArray results) {
        float f = this.x;
        if (f >= rectX + rectSize || f + this.width <= rectX) {
            return;
        }
        float f2 = this.y;
        if (f2 >= rectY + rectSize || f2 + this.height <= rectY) {
            return;
        }
        int count = this.count;
        if (count != -1) {
            float[] values = this.values;
            for (int i = 1; i < count; i += 3) {
                float px = values[i];
                float py = values[i + 1];
                float dx = px - centerX;
                float dy = py - centerY;
                float d = (dx * dx) + (dy * dy);
                if (d <= radiusSqr) {
                    results.add(values[i - 1]);
                    results.add(px);
                    results.add(py);
                    results.add(d);
                }
            }
            return;
        }
        QuadTreeFloat quadTreeFloat = this.nw;
        if (quadTreeFloat != null) {
            quadTreeFloat.query(centerX, centerY, radiusSqr, rectX, rectY, rectSize, results);
        }
        QuadTreeFloat quadTreeFloat2 = this.sw;
        if (quadTreeFloat2 != null) {
            quadTreeFloat2.query(centerX, centerY, radiusSqr, rectX, rectY, rectSize, results);
        }
        QuadTreeFloat quadTreeFloat3 = this.ne;
        if (quadTreeFloat3 != null) {
            quadTreeFloat3.query(centerX, centerY, radiusSqr, rectX, rectY, rectSize, results);
        }
        QuadTreeFloat quadTreeFloat4 = this.se;
        if (quadTreeFloat4 != null) {
            quadTreeFloat4.query(centerX, centerY, radiusSqr, rectX, rectY, rectSize, results);
        }
    }

    public boolean nearest(float x, float y, FloatArray result) {
        result.clear();
        result.add(0.0f);
        result.add(0.0f);
        result.add(0.0f);
        result.add(Float.POSITIVE_INFINITY);
        findNearestInternal(x, y, result);
        float nearValue = result.first();
        float nearX = result.get(1);
        float nearY = result.get(2);
        float nearDist = result.get(3);
        boolean found = nearDist != Float.POSITIVE_INFINITY;
        if (!found) {
            float nearDist2 = Math.max(this.width, this.height);
            nearDist = nearDist2 * nearDist2;
        }
        result.clear();
        query(x, y, (float) Math.sqrt(nearDist), result);
        int n = result.size;
        for (int i = 3; i < n; i += 4) {
            float dist = result.get(i);
            if (dist < nearDist) {
                nearDist = dist;
                nearValue = result.get(i - 3);
                nearX = result.get(i - 2);
                nearY = result.get(i - 1);
            }
        }
        if (!found && result.isEmpty()) {
            return false;
        }
        result.clear();
        result.add(nearValue);
        result.add(nearX);
        result.add(nearY);
        result.add(nearDist);
        return true;
    }

    private void findNearestInternal(float x, float y, FloatArray result) {
        float f = this.x;
        if (f >= x || f + this.width <= x) {
            return;
        }
        float f2 = this.y;
        if (f2 >= y || f2 + this.height <= y) {
            return;
        }
        int count = this.count;
        if (count != -1) {
            float nearValue = result.first();
            float nearX = result.get(1);
            float nearY = result.get(2);
            float nearDist = result.get(3);
            float[] values = this.values;
            for (int i = 1; i < count; i += 3) {
                float px = values[i];
                float py = values[i + 1];
                float dx = px - x;
                float dy = py - y;
                float dist = (dx * dx) + (dy * dy);
                if (dist < nearDist) {
                    nearDist = dist;
                    nearValue = values[i - 1];
                    nearX = px;
                    nearY = py;
                }
            }
            result.set(0, nearValue);
            result.set(1, nearX);
            result.set(2, nearY);
            result.set(3, nearDist);
            return;
        }
        QuadTreeFloat quadTreeFloat = this.nw;
        if (quadTreeFloat != null) {
            quadTreeFloat.findNearestInternal(x, y, result);
        }
        QuadTreeFloat quadTreeFloat2 = this.sw;
        if (quadTreeFloat2 != null) {
            quadTreeFloat2.findNearestInternal(x, y, result);
        }
        QuadTreeFloat quadTreeFloat3 = this.ne;
        if (quadTreeFloat3 != null) {
            quadTreeFloat3.findNearestInternal(x, y, result);
        }
        QuadTreeFloat quadTreeFloat4 = this.se;
        if (quadTreeFloat4 != null) {
            quadTreeFloat4.findNearestInternal(x, y, result);
        }
    }

    @Override // com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        if (this.count == -1) {
            QuadTreeFloat quadTreeFloat = this.nw;
            if (quadTreeFloat != null) {
                pool.free(quadTreeFloat);
                this.nw = null;
            }
            QuadTreeFloat quadTreeFloat2 = this.sw;
            if (quadTreeFloat2 != null) {
                pool.free(quadTreeFloat2);
                this.sw = null;
            }
            QuadTreeFloat quadTreeFloat3 = this.ne;
            if (quadTreeFloat3 != null) {
                pool.free(quadTreeFloat3);
                this.ne = null;
            }
            QuadTreeFloat quadTreeFloat4 = this.se;
            if (quadTreeFloat4 != null) {
                pool.free(quadTreeFloat4);
                this.se = null;
            }
        }
        this.count = 0;
        int length = this.values.length;
        int i = this.maxValues;
        if (length > i) {
            this.values = new float[i];
        }
    }
}