package com.badlogic.gdx.utils;

import java.util.Comparator;

/* loaded from: classes.dex */
public class DelayedRemovalArray<T> extends Array<T> {
    private int clear;
    private int iterating;
    private IntArray remove;

    public DelayedRemovalArray() {
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(Array array) {
        super(array);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(boolean ordered, int capacity, Class arrayType) {
        super(ordered, capacity, arrayType);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(boolean ordered, int capacity) {
        super(ordered, capacity);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(boolean ordered, T[] array, int startIndex, int count) {
        super(ordered, array, startIndex, count);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(Class arrayType) {
        super(arrayType);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(int capacity) {
        super(capacity);
        this.remove = new IntArray(0);
    }

    public DelayedRemovalArray(T[] array) {
        super(array);
        this.remove = new IntArray(0);
    }

    public void begin() {
        this.iterating++;
    }

    public void end() {
        int i = this.iterating;
        if (i == 0) {
            throw new IllegalStateException("begin must be called before end.");
        }
        this.iterating = i - 1;
        if (this.iterating == 0) {
            int i2 = this.clear;
            if (i2 > 0 && i2 == this.size) {
                this.remove.clear();
                clear();
            } else {
                int n = this.remove.size;
                for (int i3 = 0; i3 < n; i3++) {
                    int index = this.remove.pop();
                    if (index >= this.clear) {
                        removeIndex(index);
                    }
                }
                int i4 = this.clear;
                for (int i5 = i4 - 1; i5 >= 0; i5--) {
                    removeIndex(i5);
                }
            }
            this.clear = 0;
        }
    }

    private void remove(int index) {
        if (index < this.clear) {
            return;
        }
        int n = this.remove.size;
        for (int i = 0; i < n; i++) {
            int removeIndex = this.remove.get(i);
            if (index == removeIndex) {
                return;
            }
            if (index < removeIndex) {
                this.remove.insert(i, index);
                return;
            }
        }
        this.remove.add(index);
    }

    @Override // com.badlogic.gdx.utils.Array
    public boolean removeValue(T value, boolean identity) {
        if (this.iterating > 0) {
            int index = indexOf(value, identity);
            if (index == -1) {
                return false;
            }
            remove(index);
            return true;
        }
        return super.removeValue(value, identity);
    }

    @Override // com.badlogic.gdx.utils.Array
    public T removeIndex(int index) {
        if (this.iterating > 0) {
            remove(index);
            return get(index);
        }
        return (T) super.removeIndex(index);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void removeRange(int start, int end) {
        if (this.iterating > 0) {
            for (int i = end; i >= start; i--) {
                remove(i);
            }
            return;
        }
        super.removeRange(start, end);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void clear() {
        if (this.iterating > 0) {
            this.clear = this.size;
        } else {
            super.clear();
        }
    }

    @Override // com.badlogic.gdx.utils.Array
    public void set(int index, T value) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.set(index, value);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void insert(int index, T value) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.insert(index, value);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void insertRange(int index, int count) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.insertRange(index, count);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void swap(int first, int second) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.swap(first, second);
    }

    @Override // com.badlogic.gdx.utils.Array
    public T pop() {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        return (T) super.pop();
    }

    @Override // com.badlogic.gdx.utils.Array
    public void sort() {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.sort();
    }

    @Override // com.badlogic.gdx.utils.Array
    public void sort(Comparator<? super T> comparator) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.sort(comparator);
    }

    @Override // com.badlogic.gdx.utils.Array
    public void reverse() {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.reverse();
    }

    @Override // com.badlogic.gdx.utils.Array
    public void shuffle() {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.shuffle();
    }

    @Override // com.badlogic.gdx.utils.Array
    public void truncate(int newSize) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        super.truncate(newSize);
    }

    @Override // com.badlogic.gdx.utils.Array
    public T[] setSize(int newSize) {
        if (this.iterating > 0) {
            throw new IllegalStateException("Invalid between begin/end.");
        }
        return (T[]) super.setSize(newSize);
    }

    public static <T> DelayedRemovalArray<T> with(T... array) {
        return new DelayedRemovalArray<>(array);
    }
}