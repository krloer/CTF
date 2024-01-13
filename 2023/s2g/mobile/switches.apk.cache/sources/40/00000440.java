package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public abstract class FlushablePool<T> extends Pool<T> {
    protected Array<T> obtained;

    public FlushablePool() {
        this.obtained = new Array<>();
    }

    public FlushablePool(int initialCapacity) {
        super(initialCapacity);
        this.obtained = new Array<>();
    }

    public FlushablePool(int initialCapacity, int max) {
        super(initialCapacity, max);
        this.obtained = new Array<>();
    }

    @Override // com.badlogic.gdx.utils.Pool
    public T obtain() {
        T result = (T) super.obtain();
        this.obtained.add(result);
        return result;
    }

    public void flush() {
        super.freeAll(this.obtained);
        this.obtained.clear();
    }

    @Override // com.badlogic.gdx.utils.Pool
    public void free(T object) {
        this.obtained.removeValue(object, true);
        super.free(object);
    }

    @Override // com.badlogic.gdx.utils.Pool
    public void freeAll(Array<T> objects) {
        this.obtained.removeAll(objects, true);
        super.freeAll(objects);
    }
}