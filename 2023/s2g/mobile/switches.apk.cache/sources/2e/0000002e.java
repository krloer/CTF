package com.badlogic.ashley.utils;

import com.badlogic.gdx.utils.Array;
import java.util.Iterator;

/* loaded from: classes.dex */
public class ImmutableArray<T> implements Iterable<T> {
    private final Array<T> array;
    private Array.ArrayIterable<T> iterable;

    public ImmutableArray(Array<T> array) {
        this.array = array;
    }

    public int size() {
        return this.array.size;
    }

    public T get(int index) {
        return this.array.get(index);
    }

    public boolean contains(T value, boolean identity) {
        return this.array.contains(value, identity);
    }

    public int indexOf(T value, boolean identity) {
        return this.array.indexOf(value, identity);
    }

    public int lastIndexOf(T value, boolean identity) {
        return this.array.lastIndexOf(value, identity);
    }

    public T peek() {
        return this.array.peek();
    }

    public T first() {
        return this.array.first();
    }

    public T random() {
        return this.array.random();
    }

    public T[] toArray() {
        return this.array.toArray();
    }

    public <V> V[] toArray(Class<?> type) {
        return (V[]) this.array.toArray(type);
    }

    public int hashCode() {
        return this.array.hashCode();
    }

    public boolean equals(Object object) {
        return this.array.equals(object);
    }

    public String toString() {
        return this.array.toString();
    }

    public String toString(String separator) {
        return this.array.toString(separator);
    }

    @Override // java.lang.Iterable
    public Iterator<T> iterator() {
        if (this.iterable == null) {
            this.iterable = new Array.ArrayIterable<>(this.array, false);
        }
        return this.iterable.iterator();
    }
}