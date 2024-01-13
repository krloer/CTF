package com.badlogic.gdx.utils.reflect;

import java.lang.reflect.Array;

/* loaded from: classes.dex */
public final class ArrayReflection {
    public static Object newInstance(Class c, int size) {
        return Array.newInstance(c, size);
    }

    public static int getLength(Object array) {
        return Array.getLength(array);
    }

    public static Object get(Object array, int index) {
        return Array.get(array, index);
    }

    public static void set(Object array, int index, Object value) {
        Array.set(array, index, value);
    }
}