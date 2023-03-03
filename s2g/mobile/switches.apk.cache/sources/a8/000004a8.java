package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.reflect.ClassReflection;
import com.badlogic.gdx.utils.reflect.Constructor;
import com.badlogic.gdx.utils.reflect.ReflectionException;
import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public class ReflectionPool<T> extends Pool<T> {
    private final Constructor constructor;

    public ReflectionPool(Class<T> type) {
        this(type, 16, IntCompanionObject.MAX_VALUE);
    }

    public ReflectionPool(Class<T> type, int initialCapacity) {
        this(type, initialCapacity, IntCompanionObject.MAX_VALUE);
    }

    public ReflectionPool(Class<T> type, int initialCapacity, int max) {
        super(initialCapacity, max);
        this.constructor = findConstructor(type);
        if (this.constructor == null) {
            throw new RuntimeException("Class cannot be created (missing no-arg constructor): " + type.getName());
        }
    }

    private Constructor findConstructor(Class<T> type) {
        try {
            return ClassReflection.getConstructor(type, null);
        } catch (Exception e) {
            try {
                Constructor constructor = ClassReflection.getDeclaredConstructor(type, null);
                constructor.setAccessible(true);
                return constructor;
            } catch (ReflectionException e2) {
                return null;
            }
        }
    }

    @Override // com.badlogic.gdx.utils.Pool
    protected T newObject() {
        try {
            return (T) this.constructor.newInstance(null);
        } catch (Exception ex) {
            throw new GdxRuntimeException("Unable to create new instance: " + this.constructor.getDeclaringClass().getName(), ex);
        }
    }
}