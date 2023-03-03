package com.badlogic.gdx.utils.reflect;

import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/* loaded from: classes.dex */
public final class Field {
    private final java.lang.reflect.Field field;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Field(java.lang.reflect.Field field) {
        this.field = field;
    }

    public String getName() {
        return this.field.getName();
    }

    public Class getType() {
        return this.field.getType();
    }

    public Class getDeclaringClass() {
        return this.field.getDeclaringClass();
    }

    public boolean isAccessible() {
        return this.field.isAccessible();
    }

    public void setAccessible(boolean accessible) {
        this.field.setAccessible(accessible);
    }

    public boolean isDefaultAccess() {
        return (isPrivate() || isProtected() || isPublic()) ? false : true;
    }

    public boolean isFinal() {
        return Modifier.isFinal(this.field.getModifiers());
    }

    public boolean isPrivate() {
        return Modifier.isPrivate(this.field.getModifiers());
    }

    public boolean isProtected() {
        return Modifier.isProtected(this.field.getModifiers());
    }

    public boolean isPublic() {
        return Modifier.isPublic(this.field.getModifiers());
    }

    public boolean isStatic() {
        return Modifier.isStatic(this.field.getModifiers());
    }

    public boolean isTransient() {
        return Modifier.isTransient(this.field.getModifiers());
    }

    public boolean isVolatile() {
        return Modifier.isVolatile(this.field.getModifiers());
    }

    public boolean isSynthetic() {
        return this.field.isSynthetic();
    }

    public Class getElementType(int index) {
        Type genericType = this.field.getGenericType();
        if (genericType instanceof ParameterizedType) {
            Type[] actualTypes = ((ParameterizedType) genericType).getActualTypeArguments();
            if (actualTypes.length - 1 >= index) {
                Type actualType = actualTypes[index];
                if (actualType instanceof Class) {
                    return (Class) actualType;
                }
                if (actualType instanceof ParameterizedType) {
                    return (Class) ((ParameterizedType) actualType).getRawType();
                }
                if (actualType instanceof GenericArrayType) {
                    Type componentType = ((GenericArrayType) actualType).getGenericComponentType();
                    if (componentType instanceof Class) {
                        return ArrayReflection.newInstance((Class) componentType, 0).getClass();
                    }
                    return null;
                }
                return null;
            }
            return null;
        }
        return null;
    }

    public boolean isAnnotationPresent(Class<? extends java.lang.annotation.Annotation> annotationType) {
        return this.field.isAnnotationPresent(annotationType);
    }

    public Annotation[] getDeclaredAnnotations() {
        java.lang.annotation.Annotation[] annotations = this.field.getDeclaredAnnotations();
        Annotation[] result = new Annotation[annotations.length];
        for (int i = 0; i < annotations.length; i++) {
            result[i] = new Annotation(annotations[i]);
        }
        return result;
    }

    public Annotation getDeclaredAnnotation(Class<? extends java.lang.annotation.Annotation> annotationType) {
        java.lang.annotation.Annotation[] annotations = this.field.getDeclaredAnnotations();
        if (annotations == null) {
            return null;
        }
        for (java.lang.annotation.Annotation annotation : annotations) {
            if (annotation.annotationType().equals(annotationType)) {
                return new Annotation(annotation);
            }
        }
        return null;
    }

    public Object get(Object obj) throws ReflectionException {
        try {
            return this.field.get(obj);
        } catch (IllegalAccessException e) {
            throw new ReflectionException("Illegal access to field: " + getName(), e);
        } catch (IllegalArgumentException e2) {
            throw new ReflectionException("Object is not an instance of " + getDeclaringClass(), e2);
        }
    }

    public void set(Object obj, Object value) throws ReflectionException {
        try {
            this.field.set(obj, value);
        } catch (IllegalAccessException e) {
            throw new ReflectionException("Illegal access to field: " + getName(), e);
        } catch (IllegalArgumentException e2) {
            throw new ReflectionException("Argument not valid for field: " + getName(), e2);
        }
    }
}