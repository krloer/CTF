package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class Pools {
    private static final ObjectMap<Class, Pool> typePools = new ObjectMap<>();

    public static <T> Pool<T> get(Class<T> type, int max) {
        Pool pool = typePools.get(type);
        if (pool == null) {
            Pool pool2 = new ReflectionPool(type, 4, max);
            typePools.put(type, pool2);
            return pool2;
        }
        return pool;
    }

    public static <T> Pool<T> get(Class<T> type) {
        return get(type, 100);
    }

    public static <T> void set(Class<T> type, Pool<T> pool) {
        typePools.put(type, pool);
    }

    public static <T> T obtain(Class<T> type) {
        return (T) get(type).obtain();
    }

    public static void free(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("object cannot be null.");
        }
        Pool pool = typePools.get(object.getClass());
        if (pool == null) {
            return;
        }
        pool.free(object);
    }

    public static void freeAll(Array objects) {
        freeAll(objects, false);
    }

    public static void freeAll(Array objects, boolean samePool) {
        if (objects == null) {
            throw new IllegalArgumentException("objects cannot be null.");
        }
        Pool pool = null;
        int n = objects.size;
        for (int i = 0; i < n; i++) {
            Object object = objects.get(i);
            if (object != null) {
                if (pool == null) {
                    Pool pool2 = typePools.get(object.getClass());
                    pool = pool2;
                    if (pool == null) {
                    }
                }
                pool.free(object);
                if (!samePool) {
                    pool = null;
                }
            }
        }
    }

    private Pools() {
    }
}