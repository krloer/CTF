package com.badlogic.ashley.utils;

/* loaded from: classes.dex */
public class Bag<E> {
    private E[] data;
    private int size;

    public Bag() {
        this(64);
    }

    public Bag(int capacity) {
        this.size = 0;
        this.data = (E[]) new Object[capacity];
    }

    public E remove(int index) {
        E[] eArr = this.data;
        E e = eArr[index];
        int i = this.size - 1;
        this.size = i;
        eArr[index] = eArr[i];
        eArr[this.size] = null;
        return e;
    }

    public E removeLast() {
        int i = this.size;
        if (i > 0) {
            E[] eArr = this.data;
            int i2 = i - 1;
            this.size = i2;
            E e = eArr[i2];
            eArr[this.size] = null;
            return e;
        }
        return null;
    }

    public boolean remove(E e) {
        int i = 0;
        while (true) {
            int i2 = this.size;
            if (i < i2) {
                E[] eArr = this.data;
                E e2 = eArr[i];
                if (e != e2) {
                    i++;
                } else {
                    int i3 = i2 - 1;
                    this.size = i3;
                    eArr[i] = eArr[i3];
                    eArr[this.size] = null;
                    return true;
                }
            } else {
                return false;
            }
        }
    }

    public boolean contains(E e) {
        for (int i = 0; this.size > i; i++) {
            if (e == this.data[i]) {
                return true;
            }
        }
        return false;
    }

    public E get(int index) {
        return this.data[index];
    }

    public int size() {
        return this.size;
    }

    public int getCapacity() {
        return this.data.length;
    }

    public boolean isIndexWithinBounds(int index) {
        return index < getCapacity();
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    public void add(E e) {
        if (this.size == this.data.length) {
            grow();
        }
        E[] eArr = this.data;
        int i = this.size;
        this.size = i + 1;
        eArr[i] = e;
    }

    public void set(int index, E e) {
        if (index >= this.data.length) {
            grow(index * 2);
        }
        this.size = index + 1;
        this.data[index] = e;
    }

    public void clear() {
        for (int i = 0; i < this.size; i++) {
            this.data[i] = null;
        }
        this.size = 0;
    }

    private void grow() {
        int newCapacity = ((this.data.length * 3) / 2) + 1;
        grow(newCapacity);
    }

    private void grow(int newCapacity) {
        E[] oldData = this.data;
        this.data = (E[]) new Object[newCapacity];
        System.arraycopy(oldData, 0, this.data, 0, oldData.length);
    }
}