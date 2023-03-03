package com.badlogic.gdx.utils;

import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class LongQueue {
    protected int head;
    public int size;
    protected int tail;
    protected long[] values;

    public LongQueue() {
        this(16);
    }

    public LongQueue(int initialSize) {
        this.head = 0;
        this.tail = 0;
        this.size = 0;
        this.values = new long[initialSize];
    }

    public void addLast(long value) {
        long[] values = this.values;
        if (this.size == values.length) {
            resize(values.length << 1);
            values = this.values;
        }
        int i = this.tail;
        this.tail = i + 1;
        values[i] = value;
        if (this.tail == values.length) {
            this.tail = 0;
        }
        this.size++;
    }

    public void addFirst(long value) {
        long[] values = this.values;
        if (this.size == values.length) {
            resize(values.length << 1);
            values = this.values;
        }
        int head = this.head - 1;
        if (head == -1) {
            head = values.length - 1;
        }
        values[head] = value;
        this.head = head;
        this.size++;
    }

    public void ensureCapacity(int additional) {
        int needed = this.size + additional;
        if (this.values.length < needed) {
            resize(needed);
        }
    }

    protected void resize(int newSize) {
        long[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        long[] newArray = new long[newSize];
        if (head < tail) {
            System.arraycopy(values, head, newArray, 0, tail - head);
        } else if (this.size > 0) {
            int rest = values.length - head;
            System.arraycopy(values, head, newArray, 0, rest);
            System.arraycopy(values, 0, newArray, rest, tail);
        }
        this.values = newArray;
        this.head = 0;
        this.tail = this.size;
    }

    public long removeFirst() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        long[] values = this.values;
        int i = this.head;
        long result = values[i];
        this.head = i + 1;
        if (this.head == values.length) {
            this.head = 0;
        }
        this.size--;
        return result;
    }

    public long removeLast() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        long[] values = this.values;
        int tail = this.tail - 1;
        if (tail == -1) {
            tail = values.length - 1;
        }
        long result = values[tail];
        this.tail = tail;
        this.size--;
        return result;
    }

    public int indexOf(long value) {
        if (this.size == 0) {
            return -1;
        }
        long[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        if (head < tail) {
            for (int i = head; i < tail; i++) {
                if (values[i] == value) {
                    return i - head;
                }
            }
        } else {
            int n = values.length;
            for (int i2 = head; i2 < n; i2++) {
                if (values[i2] == value) {
                    return i2 - head;
                }
            }
            for (int i3 = 0; i3 < tail; i3++) {
                if (values[i3] == value) {
                    return (values.length + i3) - head;
                }
            }
        }
        return -1;
    }

    public boolean removeValue(long value) {
        int index = indexOf(value);
        if (index == -1) {
            return false;
        }
        removeIndex(index);
        return true;
    }

    public long removeIndex(int index) {
        long value;
        if (index < 0) {
            throw new IndexOutOfBoundsException("index can't be < 0: " + index);
        } else if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        } else {
            long[] values = this.values;
            int head = this.head;
            int tail = this.tail;
            int index2 = index + head;
            if (head < tail) {
                value = values[index2];
                System.arraycopy(values, index2 + 1, values, index2, tail - index2);
                this.tail--;
            } else if (index2 >= values.length) {
                int index3 = index2 - values.length;
                value = values[index3];
                System.arraycopy(values, index3 + 1, values, index3, tail - index3);
                this.tail--;
            } else {
                value = values[index2];
                System.arraycopy(values, head, values, head + 1, index2 - head);
                this.head++;
                if (this.head == values.length) {
                    this.head = 0;
                }
            }
            this.size--;
            return value;
        }
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    public long first() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        return this.values[this.head];
    }

    public long last() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        long[] values = this.values;
        int tail = this.tail - 1;
        if (tail == -1) {
            tail = values.length - 1;
        }
        return values[tail];
    }

    public long get(int index) {
        if (index < 0) {
            throw new IndexOutOfBoundsException("index can't be < 0: " + index);
        } else if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        } else {
            long[] values = this.values;
            int i = this.head + index;
            if (i >= values.length) {
                i -= values.length;
            }
            return values[i];
        }
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        this.head = 0;
        this.tail = 0;
        this.size = 0;
    }

    public String toString() {
        if (this.size == 0) {
            return "[]";
        }
        long[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        StringBuilder sb = new StringBuilder(64);
        sb.append('[');
        sb.append(values[head]);
        for (int i = (head + 1) % values.length; i != tail; i = (i + 1) % values.length) {
            sb.append(", ").append(values[i]);
        }
        sb.append(']');
        return sb.toString();
    }

    public String toString(String separator) {
        if (this.size == 0) {
            return BuildConfig.FLAVOR;
        }
        long[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        StringBuilder sb = new StringBuilder(64);
        sb.append(values[head]);
        for (int i = (head + 1) % values.length; i != tail; i = (i + 1) % values.length) {
            sb.append(separator).append(values[i]);
        }
        return sb.toString();
    }

    public int hashCode() {
        int size = this.size;
        long[] values = this.values;
        int backingLength = values.length;
        int index = this.head;
        int hash = size + 1;
        for (int s = 0; s < size; s++) {
            long value = values[index];
            hash += ((int) ((value >>> 32) ^ value)) * 31;
            index++;
            if (index == backingLength) {
                index = 0;
            }
        }
        return hash;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || !(o instanceof LongQueue)) {
            return false;
        }
        LongQueue q = (LongQueue) o;
        int size = this.size;
        if (q.size != size) {
            return false;
        }
        long[] myValues = this.values;
        int myBackingLength = myValues.length;
        long[] itsValues = q.values;
        int itsBackingLength = itsValues.length;
        int myIndex = this.head;
        int itsIndex = q.head;
        for (int s = 0; s < size; s++) {
            if (myValues[myIndex] != itsValues[itsIndex]) {
                return false;
            }
            myIndex++;
            itsIndex++;
            if (myIndex == myBackingLength) {
                myIndex = 0;
            }
            if (itsIndex == itsBackingLength) {
                itsIndex = 0;
            }
        }
        return true;
    }
}