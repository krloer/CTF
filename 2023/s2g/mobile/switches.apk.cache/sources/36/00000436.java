package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.MathUtils;
import java.util.Arrays;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class CharArray {
    public char[] items;
    public boolean ordered;
    public int size;

    public CharArray() {
        this(true, 16);
    }

    public CharArray(int capacity) {
        this(true, capacity);
    }

    public CharArray(boolean ordered, int capacity) {
        this.ordered = ordered;
        this.items = new char[capacity];
    }

    public CharArray(CharArray array) {
        this.ordered = array.ordered;
        this.size = array.size;
        int i = this.size;
        this.items = new char[i];
        System.arraycopy(array.items, 0, this.items, 0, i);
    }

    public CharArray(char[] array) {
        this(true, array, 0, array.length);
    }

    public CharArray(boolean ordered, char[] array, int startIndex, int count) {
        this(ordered, count);
        this.size = count;
        System.arraycopy(array, startIndex, this.items, 0, count);
    }

    public void add(char value) {
        char[] items = this.items;
        int i = this.size;
        if (i == items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        this.size = i2 + 1;
        items[i2] = value;
    }

    public void add(char value1, char value2) {
        char[] items = this.items;
        int i = this.size;
        if (i + 1 >= items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        items[i2] = value1;
        items[i2 + 1] = value2;
        this.size = i2 + 2;
    }

    public void add(char value1, char value2, char value3) {
        char[] items = this.items;
        int i = this.size;
        if (i + 2 >= items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        items[i2] = value1;
        items[i2 + 1] = value2;
        items[i2 + 2] = value3;
        this.size = i2 + 3;
    }

    public void add(char value1, char value2, char value3, char value4) {
        char[] items = this.items;
        int i = this.size;
        if (i + 3 >= items.length) {
            items = resize(Math.max(8, (int) (i * 1.8f)));
        }
        int i2 = this.size;
        items[i2] = value1;
        items[i2 + 1] = value2;
        items[i2 + 2] = value3;
        items[i2 + 3] = value4;
        this.size = i2 + 4;
    }

    public void addAll(CharArray array) {
        addAll(array.items, 0, array.size);
    }

    public void addAll(CharArray array, int offset, int length) {
        if (offset + length > array.size) {
            throw new IllegalArgumentException("offset + length must be <= size: " + offset + " + " + length + " <= " + array.size);
        }
        addAll(array.items, offset, length);
    }

    public void addAll(char... array) {
        addAll(array, 0, array.length);
    }

    public void addAll(char[] array, int offset, int length) {
        char[] items = this.items;
        int sizeNeeded = this.size + length;
        if (sizeNeeded > items.length) {
            items = resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
        System.arraycopy(array, offset, items, this.size, length);
        this.size += length;
    }

    public char get(int index) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        return this.items[index];
    }

    public void set(int index, char value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        this.items[index] = value;
    }

    public void incr(int index, char value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        char[] cArr = this.items;
        cArr[index] = (char) (cArr[index] + value);
    }

    public void incr(char value) {
        char[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            items[i] = (char) (items[i] + value);
        }
    }

    public void mul(int index, char value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        char[] cArr = this.items;
        cArr[index] = (char) (cArr[index] * value);
    }

    public void mul(char value) {
        char[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            items[i] = (char) (items[i] * value);
        }
    }

    public void insert(int index, char value) {
        int i = this.size;
        if (index > i) {
            throw new IndexOutOfBoundsException("index can't be > size: " + index + " > " + this.size);
        }
        char[] items = this.items;
        if (i == items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        if (this.ordered) {
            System.arraycopy(items, index, items, index + 1, this.size - index);
        } else {
            items[this.size] = items[index];
        }
        this.size++;
        items[index] = value;
    }

    public void insertRange(int index, int count) {
        int i = this.size;
        if (index > i) {
            throw new IndexOutOfBoundsException("index can't be > size: " + index + " > " + this.size);
        }
        int sizeNeeded = i + count;
        if (sizeNeeded > this.items.length) {
            this.items = resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
        char[] cArr = this.items;
        System.arraycopy(cArr, index, cArr, index + count, this.size - index);
        this.size = sizeNeeded;
    }

    public void swap(int first, int second) {
        int i = this.size;
        if (first >= i) {
            throw new IndexOutOfBoundsException("first can't be >= size: " + first + " >= " + this.size);
        } else if (second >= i) {
            throw new IndexOutOfBoundsException("second can't be >= size: " + second + " >= " + this.size);
        } else {
            char[] items = this.items;
            char firstValue = items[first];
            items[first] = items[second];
            items[second] = firstValue;
        }
    }

    public boolean contains(char value) {
        int i = this.size - 1;
        char[] items = this.items;
        while (i >= 0) {
            int i2 = i - 1;
            if (items[i] == value) {
                return true;
            }
            i = i2;
        }
        return false;
    }

    public int indexOf(char value) {
        char[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            if (items[i] == value) {
                return i;
            }
        }
        return -1;
    }

    public int lastIndexOf(char value) {
        char[] items = this.items;
        for (int i = this.size - 1; i >= 0; i--) {
            if (items[i] == value) {
                return i;
            }
        }
        return -1;
    }

    public boolean removeValue(char value) {
        char[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            if (items[i] == value) {
                removeIndex(i);
                return true;
            }
        }
        return false;
    }

    public char removeIndex(int index) {
        int i = this.size;
        if (index >= i) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        char[] items = this.items;
        char value = items[index];
        this.size = i - 1;
        if (this.ordered) {
            System.arraycopy(items, index + 1, items, index, this.size - index);
        } else {
            items[index] = items[this.size];
        }
        return value;
    }

    public void removeRange(int start, int end) {
        int n = this.size;
        if (end >= n) {
            throw new IndexOutOfBoundsException("end can't be >= size: " + end + " >= " + this.size);
        } else if (start > end) {
            throw new IndexOutOfBoundsException("start can't be > end: " + start + " > " + end);
        } else {
            int count = (end - start) + 1;
            int lastIndex = n - count;
            if (this.ordered) {
                char[] cArr = this.items;
                System.arraycopy(cArr, start + count, cArr, start, n - (start + count));
            } else {
                int i = Math.max(lastIndex, end + 1);
                char[] cArr2 = this.items;
                System.arraycopy(cArr2, i, cArr2, start, n - i);
            }
            this.size = n - count;
        }
    }

    public boolean removeAll(CharArray array) {
        int size = this.size;
        char[] items = this.items;
        int n = array.size;
        for (int i = 0; i < n; i++) {
            char item = array.get(i);
            int ii = 0;
            while (true) {
                if (ii < size) {
                    if (item != items[ii]) {
                        ii++;
                    } else {
                        removeIndex(ii);
                        size--;
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        return size != size;
    }

    public char pop() {
        char[] cArr = this.items;
        int i = this.size - 1;
        this.size = i;
        return cArr[i];
    }

    public char peek() {
        return this.items[this.size - 1];
    }

    public char first() {
        if (this.size == 0) {
            throw new IllegalStateException("Array is empty.");
        }
        return this.items[0];
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    public void clear() {
        this.size = 0;
    }

    public char[] shrink() {
        int length = this.items.length;
        int i = this.size;
        if (length != i) {
            resize(i);
        }
        return this.items;
    }

    public char[] ensureCapacity(int additionalCapacity) {
        if (additionalCapacity < 0) {
            throw new IllegalArgumentException("additionalCapacity must be >= 0: " + additionalCapacity);
        }
        int sizeNeeded = this.size + additionalCapacity;
        if (sizeNeeded > this.items.length) {
            resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
        return this.items;
    }

    public char[] setSize(int newSize) {
        if (newSize < 0) {
            throw new IllegalArgumentException("newSize must be >= 0: " + newSize);
        }
        if (newSize > this.items.length) {
            resize(Math.max(8, newSize));
        }
        this.size = newSize;
        return this.items;
    }

    protected char[] resize(int newSize) {
        char[] newItems = new char[newSize];
        char[] items = this.items;
        System.arraycopy(items, 0, newItems, 0, Math.min(this.size, newItems.length));
        this.items = newItems;
        return newItems;
    }

    public void sort() {
        Arrays.sort(this.items, 0, this.size);
    }

    public void reverse() {
        char[] items = this.items;
        int i = this.size;
        int lastIndex = i - 1;
        int n = i / 2;
        for (int i2 = 0; i2 < n; i2++) {
            int ii = lastIndex - i2;
            char temp = items[i2];
            items[i2] = items[ii];
            items[ii] = temp;
        }
    }

    public void shuffle() {
        char[] items = this.items;
        for (int i = this.size - 1; i >= 0; i--) {
            int ii = MathUtils.random(i);
            char temp = items[i];
            items[i] = items[ii];
            items[ii] = temp;
        }
    }

    public void truncate(int newSize) {
        if (this.size > newSize) {
            this.size = newSize;
        }
    }

    public char random() {
        int i = this.size;
        if (i == 0) {
            return (char) 0;
        }
        return this.items[MathUtils.random(0, i - 1)];
    }

    public char[] toArray() {
        int i = this.size;
        char[] array = new char[i];
        System.arraycopy(this.items, 0, array, 0, i);
        return array;
    }

    public int hashCode() {
        if (this.ordered) {
            char[] items = this.items;
            int h = 1;
            int n = this.size;
            for (int i = 0; i < n; i++) {
                h = (h * 31) + items[i];
            }
            return h;
        }
        return super.hashCode();
    }

    public boolean equals(Object object) {
        int n;
        if (object == this) {
            return true;
        }
        if (this.ordered && (object instanceof CharArray)) {
            CharArray array = (CharArray) object;
            if (array.ordered && (n = this.size) == array.size) {
                char[] items1 = this.items;
                char[] items2 = array.items;
                for (int i = 0; i < n; i++) {
                    if (items1[i] != items2[i]) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    public String toString() {
        if (this.size == 0) {
            return "[]";
        }
        char[] items = this.items;
        StringBuilder buffer = new StringBuilder(32);
        buffer.append('[');
        buffer.append(items[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(", ");
            buffer.append(items[i]);
        }
        buffer.append(']');
        return buffer.toString();
    }

    public String toString(String separator) {
        if (this.size == 0) {
            return BuildConfig.FLAVOR;
        }
        char[] items = this.items;
        StringBuilder buffer = new StringBuilder(32);
        buffer.append(items[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(separator);
            buffer.append(items[i]);
        }
        return buffer.toString();
    }

    public static CharArray with(char... array) {
        return new CharArray(array);
    }
}