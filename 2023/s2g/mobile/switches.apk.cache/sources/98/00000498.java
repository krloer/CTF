package com.badlogic.gdx.utils;

import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public abstract class Pool<T> {
    private final Array<T> freeObjects;
    public final int max;
    public int peak;

    /* loaded from: classes.dex */
    public interface Poolable {
        void reset();
    }

    protected abstract T newObject();

    public Pool() {
        this(16, IntCompanionObject.MAX_VALUE);
    }

    public Pool(int initialCapacity) {
        this(initialCapacity, IntCompanionObject.MAX_VALUE);
    }

    public Pool(int initialCapacity, int max) {
        this.freeObjects = new Array<>(false, initialCapacity);
        this.max = max;
    }

    public T obtain() {
        return this.freeObjects.size == 0 ? newObject() : this.freeObjects.pop();
    }

    public void free(T object) {
        if (object == null) {
            throw new IllegalArgumentException("object cannot be null.");
        }
        if (this.freeObjects.size < this.max) {
            this.freeObjects.add(object);
            this.peak = Math.max(this.peak, this.freeObjects.size);
            reset(object);
            return;
        }
        discard(object);
    }

    public void fill(int size) {
        for (int i = 0; i < size; i++) {
            if (this.freeObjects.size < this.max) {
                this.freeObjects.add(newObject());
            }
        }
        int i2 = this.peak;
        this.peak = Math.max(i2, this.freeObjects.size);
    }

    protected void reset(T object) {
        if (object instanceof Poolable) {
            ((Poolable) object).reset();
        }
    }

    protected void discard(T object) {
    }

    public void freeAll(Array<T> objects) {
        if (objects == null) {
            throw new IllegalArgumentException("objects cannot be null.");
        }
        Array<T> freeObjects = this.freeObjects;
        int max = this.max;
        int n = objects.size;
        for (int i = 0; i < n; i++) {
            T object = objects.get(i);
            if (object != null) {
                if (freeObjects.size < max) {
                    freeObjects.add(object);
                    reset(object);
                } else {
                    discard(object);
                }
            }
        }
        int i2 = this.peak;
        this.peak = Math.max(i2, freeObjects.size);
    }

    public void clear() {
        for (int i = 0; i < this.freeObjects.size; i++) {
            T obj = this.freeObjects.pop();
            discard(obj);
        }
    }

    public int getFree() {
        return this.freeObjects.size;
    }
}