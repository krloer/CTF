package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.MathUtils;
import java.util.Arrays;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ShortArray {
    public short[] items;
    public boolean ordered;
    public int size;

    public ShortArray() {
        this(true, 16);
    }

    public ShortArray(int capacity) {
        this(true, capacity);
    }

    public ShortArray(boolean ordered, int capacity) {
        this.ordered = ordered;
        this.items = new short[capacity];
    }

    public ShortArray(ShortArray array) {
        this.ordered = array.ordered;
        this.size = array.size;
        int i = this.size;
        this.items = new short[i];
        System.arraycopy(array.items, 0, this.items, 0, i);
    }

    public ShortArray(short[] array) {
        this(true, array, 0, array.length);
    }

    public ShortArray(boolean ordered, short[] array, int startIndex, int count) {
        this(ordered, count);
        this.size = count;
        System.arraycopy(array, startIndex, this.items, 0, count);
    }

    public void add(int value) {
        short[] items = this.items;
        int i = this.size;
        if (i == items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        this.size = i2 + 1;
        items[i2] = (short) value;
    }

    public void add(short value) {
        short[] items = this.items;
        int i = this.size;
        if (i == items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        this.size = i2 + 1;
        items[i2] = value;
    }

    public void add(short value1, short value2) {
        short[] items = this.items;
        int i = this.size;
        if (i + 1 >= items.length) {
            items = resize(Math.max(8, (int) (i * 1.75f)));
        }
        int i2 = this.size;
        items[i2] = value1;
        items[i2 + 1] = value2;
        this.size = i2 + 2;
    }

    public void add(short value1, short value2, short value3) {
        short[] items = this.items;
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

    public void add(short value1, short value2, short value3, short value4) {
        short[] items = this.items;
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

    public void addAll(ShortArray array) {
        addAll(array.items, 0, array.size);
    }

    public void addAll(ShortArray array, int offset, int length) {
        if (offset + length > array.size) {
            throw new IllegalArgumentException("offset + length must be <= size: " + offset + " + " + length + " <= " + array.size);
        }
        addAll(array.items, offset, length);
    }

    public void addAll(short... array) {
        addAll(array, 0, array.length);
    }

    public void addAll(short[] array, int offset, int length) {
        short[] items = this.items;
        int sizeNeeded = this.size + length;
        if (sizeNeeded > items.length) {
            items = resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
        System.arraycopy(array, offset, items, this.size, length);
        this.size += length;
    }

    public short get(int index) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        return this.items[index];
    }

    public void set(int index, short value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        this.items[index] = value;
    }

    public void incr(int index, short value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        short[] sArr = this.items;
        sArr[index] = (short) (sArr[index] + value);
    }

    public void incr(short value) {
        short[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            items[i] = (short) (items[i] + value);
        }
    }

    public void mul(int index, short value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        short[] sArr = this.items;
        sArr[index] = (short) (sArr[index] * value);
    }

    public void mul(short value) {
        short[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            items[i] = (short) (items[i] * value);
        }
    }

    public void insert(int index, short value) {
        int i = this.size;
        if (index > i) {
            throw new IndexOutOfBoundsException("index can't be > size: " + index + " > " + this.size);
        }
        short[] items = this.items;
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
        short[] sArr = this.items;
        System.arraycopy(sArr, index, sArr, index + count, this.size - index);
        this.size = sizeNeeded;
    }

    public void swap(int first, int second) {
        int i = this.size;
        if (first >= i) {
            throw new IndexOutOfBoundsException("first can't be >= size: " + first + " >= " + this.size);
        } else if (second >= i) {
            throw new IndexOutOfBoundsException("second can't be >= size: " + second + " >= " + this.size);
        } else {
            short[] items = this.items;
            short firstValue = items[first];
            items[first] = items[second];
            items[second] = firstValue;
        }
    }

    public boolean contains(short value) {
        int i = this.size - 1;
        short[] items = this.items;
        while (i >= 0) {
            int i2 = i - 1;
            if (items[i] == value) {
                return true;
            }
            i = i2;
        }
        return false;
    }

    public int indexOf(short value) {
        short[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            if (items[i] == value) {
                return i;
            }
        }
        return -1;
    }

    public int lastIndexOf(char value) {
        short[] items = this.items;
        for (int i = this.size - 1; i >= 0; i--) {
            if (items[i] == value) {
                return i;
            }
        }
        return -1;
    }

    public boolean removeValue(short value) {
        short[] items = this.items;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            if (items[i] == value) {
                removeIndex(i);
                return true;
            }
        }
        return false;
    }

    public short removeIndex(int index) {
        int i = this.size;
        if (index >= i) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        }
        short[] items = this.items;
        short value = items[index];
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
                short[] sArr = this.items;
                System.arraycopy(sArr, start + count, sArr, start, n - (start + count));
            } else {
                int i = Math.max(lastIndex, end + 1);
                short[] sArr2 = this.items;
                System.arraycopy(sArr2, i, sArr2, start, n - i);
            }
            this.size = n - count;
        }
    }

    public boolean removeAll(ShortArray array) {
        int size = this.size;
        short[] items = this.items;
        int n = array.size;
        for (int i = 0; i < n; i++) {
            short item = array.get(i);
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

    public short pop() {
        short[] sArr = this.items;
        int i = this.size - 1;
        this.size = i;
        return sArr[i];
    }

    public short peek() {
        return this.items[this.size - 1];
    }

    public short first() {
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

    public short[] shrink() {
        int length = this.items.length;
        int i = this.size;
        if (length != i) {
            resize(i);
        }
        return this.items;
    }

    public short[] ensureCapacity(int additionalCapacity) {
        if (additionalCapacity < 0) {
            throw new IllegalArgumentException("additionalCapacity must be >= 0: " + additionalCapacity);
        }
        int sizeNeeded = this.size + additionalCapacity;
        if (sizeNeeded > this.items.length) {
            resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
        return this.items;
    }

    public short[] setSize(int newSize) {
        if (newSize < 0) {
            throw new IllegalArgumentException("newSize must be >= 0: " + newSize);
        }
        if (newSize > this.items.length) {
            resize(Math.max(8, newSize));
        }
        this.size = newSize;
        return this.items;
    }

    protected short[] resize(int newSize) {
        short[] newItems = new short[newSize];
        short[] items = this.items;
        System.arraycopy(items, 0, newItems, 0, Math.min(this.size, newItems.length));
        this.items = newItems;
        return newItems;
    }

    public void sort() {
        Arrays.sort(this.items, 0, this.size);
    }

    public void reverse() {
        short[] items = this.items;
        int i = this.size;
        int lastIndex = i - 1;
        int n = i / 2;
        for (int i2 = 0; i2 < n; i2++) {
            int ii = lastIndex - i2;
            short temp = items[i2];
            items[i2] = items[ii];
            items[ii] = temp;
        }
    }

    public void shuffle() {
        short[] items = this.items;
        for (int i = this.size - 1; i >= 0; i--) {
            int ii = MathUtils.random(i);
            short temp = items[i];
            items[i] = items[ii];
            items[ii] = temp;
        }
    }

    public void truncate(int newSize) {
        if (this.size > newSize) {
            this.size = newSize;
        }
    }

    public short random() {
        int i = this.size;
        if (i == 0) {
            return (short) 0;
        }
        return this.items[MathUtils.random(0, i - 1)];
    }

    public short[] toArray() {
        int i = this.size;
        short[] array = new short[i];
        System.arraycopy(this.items, 0, array, 0, i);
        return array;
    }

    public int hashCode() {
        if (this.ordered) {
            short[] items = this.items;
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
        if (this.ordered && (object instanceof ShortArray)) {
            ShortArray array = (ShortArray) object;
            if (array.ordered && (n = this.size) == array.size) {
                short[] items1 = this.items;
                short[] items2 = array.items;
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
        short[] items = this.items;
        StringBuilder buffer = new StringBuilder(32);
        buffer.append('[');
        buffer.append((int) items[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(", ");
            buffer.append((int) items[i]);
        }
        buffer.append(']');
        return buffer.toString();
    }

    public String toString(String separator) {
        if (this.size == 0) {
            return BuildConfig.FLAVOR;
        }
        short[] items = this.items;
        StringBuilder buffer = new StringBuilder(32);
        buffer.append((int) items[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(separator);
            buffer.append((int) items[i]);
        }
        return buffer.toString();
    }

    public static ShortArray with(short... array) {
        return new ShortArray(array);
    }
}