package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.reflect.ArrayReflection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Queue<T> implements Iterable<T> {
    protected int head;
    private transient QueueIterable iterable;
    public int size;
    protected int tail;
    protected T[] values;

    public Queue() {
        this(16);
    }

    public Queue(int initialSize) {
        this.head = 0;
        this.tail = 0;
        this.size = 0;
        this.values = (T[]) new Object[initialSize];
    }

    public Queue(int initialSize, Class<T> type) {
        this.head = 0;
        this.tail = 0;
        this.size = 0;
        this.values = (T[]) ((Object[]) ArrayReflection.newInstance(type, initialSize));
    }

    public void addLast(T object) {
        T[] values = this.values;
        if (this.size == values.length) {
            resize(values.length << 1);
            values = this.values;
        }
        int i = this.tail;
        this.tail = i + 1;
        values[i] = object;
        if (this.tail == values.length) {
            this.tail = 0;
        }
        this.size++;
    }

    public void addFirst(T object) {
        T[] values = this.values;
        if (this.size == values.length) {
            resize(values.length << 1);
            values = this.values;
        }
        int head = this.head - 1;
        if (head == -1) {
            head = values.length - 1;
        }
        values[head] = object;
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
        T[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        T[] newArray = (T[]) ((Object[]) ArrayReflection.newInstance(values.getClass().getComponentType(), newSize));
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

    public T removeFirst() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        T[] values = this.values;
        int i = this.head;
        T result = values[i];
        values[i] = null;
        this.head = i + 1;
        if (this.head == values.length) {
            this.head = 0;
        }
        this.size--;
        return result;
    }

    public T removeLast() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        T[] values = this.values;
        int tail = this.tail - 1;
        if (tail == -1) {
            tail = values.length - 1;
        }
        T result = values[tail];
        values[tail] = null;
        this.tail = tail;
        this.size--;
        return result;
    }

    public int indexOf(T value, boolean identity) {
        if (this.size == 0) {
            return -1;
        }
        T[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        if (identity || value == null) {
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
        } else if (head < tail) {
            for (int i4 = head; i4 < tail; i4++) {
                if (value.equals(values[i4])) {
                    return i4 - head;
                }
            }
        } else {
            int n2 = values.length;
            for (int i5 = head; i5 < n2; i5++) {
                if (value.equals(values[i5])) {
                    return i5 - head;
                }
            }
            for (int i6 = 0; i6 < tail; i6++) {
                if (value.equals(values[i6])) {
                    return (values.length + i6) - head;
                }
            }
        }
        return -1;
    }

    public boolean removeValue(T value, boolean identity) {
        int index = indexOf(value, identity);
        if (index == -1) {
            return false;
        }
        removeIndex(index);
        return true;
    }

    public T removeIndex(int index) {
        T value;
        if (index < 0) {
            throw new IndexOutOfBoundsException("index can't be < 0: " + index);
        } else if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        } else {
            T[] values = this.values;
            int head = this.head;
            int tail = this.tail;
            int index2 = index + head;
            if (head < tail) {
                value = values[index2];
                System.arraycopy(values, index2 + 1, values, index2, tail - index2);
                values[tail] = null;
                this.tail--;
            } else if (index2 >= values.length) {
                int index3 = index2 - values.length;
                value = values[index3];
                System.arraycopy(values, index3 + 1, values, index3, tail - index3);
                this.tail--;
            } else {
                value = values[index2];
                System.arraycopy(values, head, values, head + 1, index2 - head);
                values[head] = null;
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

    public T first() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        return this.values[this.head];
    }

    public T last() {
        if (this.size == 0) {
            throw new NoSuchElementException("Queue is empty.");
        }
        T[] values = this.values;
        int tail = this.tail - 1;
        if (tail == -1) {
            tail = values.length - 1;
        }
        return values[tail];
    }

    public T get(int index) {
        if (index < 0) {
            throw new IndexOutOfBoundsException("index can't be < 0: " + index);
        } else if (index >= this.size) {
            throw new IndexOutOfBoundsException("index can't be >= size: " + index + " >= " + this.size);
        } else {
            T[] values = this.values;
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
        T[] values = this.values;
        int head = this.head;
        int tail = this.tail;
        if (head < tail) {
            for (int i = head; i < tail; i++) {
                values[i] = null;
            }
        } else {
            for (int i2 = head; i2 < values.length; i2++) {
                values[i2] = null;
            }
            for (int i3 = 0; i3 < tail; i3++) {
                values[i3] = null;
            }
        }
        this.head = 0;
        this.tail = 0;
        this.size = 0;
    }

    @Override // java.lang.Iterable
    public Iterator<T> iterator() {
        if (Collections.allocateIterators) {
            return new QueueIterator(this, true);
        }
        if (this.iterable == null) {
            this.iterable = new QueueIterable(this);
        }
        return this.iterable.iterator();
    }

    public String toString() {
        if (this.size == 0) {
            return "[]";
        }
        T[] values = this.values;
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
        T[] values = this.values;
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
        T[] values = this.values;
        int backingLength = values.length;
        int index = this.head;
        int hash = size + 1;
        for (int s = 0; s < size; s++) {
            T value = values[index];
            hash *= 31;
            if (value != null) {
                hash += value.hashCode();
            }
            index++;
            if (index == backingLength) {
                index = 0;
            }
        }
        return hash;
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x003d A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public boolean equals(java.lang.Object r15) {
        /*
            r14 = this;
            r0 = 1
            if (r14 != r15) goto L4
            return r0
        L4:
            r1 = 0
            if (r15 == 0) goto L41
            boolean r2 = r15 instanceof com.badlogic.gdx.utils.Queue
            if (r2 != 0) goto Lc
            goto L41
        Lc:
            r2 = r15
            com.badlogic.gdx.utils.Queue r2 = (com.badlogic.gdx.utils.Queue) r2
            int r3 = r14.size
            int r4 = r2.size
            if (r4 == r3) goto L16
            return r1
        L16:
            T[] r4 = r14.values
            int r5 = r4.length
            T[] r6 = r2.values
            int r7 = r6.length
            int r8 = r14.head
            int r9 = r2.head
            r10 = 0
        L21:
            if (r10 >= r3) goto L40
            r11 = r4[r8]
            r12 = r6[r9]
            if (r11 != 0) goto L2c
            if (r12 != 0) goto L32
            goto L33
        L2c:
            boolean r13 = r11.equals(r12)
            if (r13 != 0) goto L33
        L32:
            return r1
        L33:
            int r8 = r8 + 1
            int r9 = r9 + 1
            if (r8 != r5) goto L3a
            r8 = 0
        L3a:
            if (r9 != r7) goto L3d
            r9 = 0
        L3d:
            int r10 = r10 + 1
            goto L21
        L40:
            return r0
        L41:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.Queue.equals(java.lang.Object):boolean");
    }

    public boolean equalsIdentity(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || !(o instanceof Queue)) {
            return false;
        }
        Queue<?> q = (Queue) o;
        int size = this.size;
        if (q.size != size) {
            return false;
        }
        Object[] myValues = this.values;
        int myBackingLength = myValues.length;
        Object[] itsValues = q.values;
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

    /* loaded from: classes.dex */
    public static class QueueIterator<T> implements Iterator<T>, Iterable<T> {
        private final boolean allowRemove;
        int index;
        private final Queue<T> queue;
        boolean valid;

        public QueueIterator(Queue<T> queue) {
            this(queue, true);
        }

        public QueueIterator(Queue<T> queue, boolean allowRemove) {
            this.valid = true;
            this.queue = queue;
            this.allowRemove = allowRemove;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.valid) {
                return this.index < this.queue.size;
            }
            throw new GdxRuntimeException("#iterator() cannot be used nested.");
        }

        @Override // java.util.Iterator
        public T next() {
            if (this.index >= this.queue.size) {
                throw new NoSuchElementException(String.valueOf(this.index));
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            Queue<T> queue = this.queue;
            int i = this.index;
            this.index = i + 1;
            return queue.get(i);
        }

        @Override // java.util.Iterator
        public void remove() {
            if (!this.allowRemove) {
                throw new GdxRuntimeException("Remove not allowed.");
            }
            this.index--;
            this.queue.removeIndex(this.index);
        }

        public void reset() {
            this.index = 0;
        }

        @Override // java.lang.Iterable
        public Iterator<T> iterator() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static class QueueIterable<T> implements Iterable<T> {
        private final boolean allowRemove;
        private QueueIterator iterator1;
        private QueueIterator iterator2;
        private final Queue<T> queue;

        public QueueIterable(Queue<T> queue) {
            this(queue, true);
        }

        public QueueIterable(Queue<T> queue, boolean allowRemove) {
            this.queue = queue;
            this.allowRemove = allowRemove;
        }

        @Override // java.lang.Iterable
        public Iterator<T> iterator() {
            if (Collections.allocateIterators) {
                return new QueueIterator(this.queue, this.allowRemove);
            }
            if (this.iterator1 == null) {
                this.iterator1 = new QueueIterator(this.queue, this.allowRemove);
                this.iterator2 = new QueueIterator(this.queue, this.allowRemove);
            }
            if (!this.iterator1.valid) {
                QueueIterator queueIterator = this.iterator1;
                queueIterator.index = 0;
                queueIterator.valid = true;
                this.iterator2.valid = false;
                return queueIterator;
            }
            QueueIterator queueIterator2 = this.iterator2;
            queueIterator2.index = 0;
            queueIterator2.valid = true;
            this.iterator1.valid = false;
            return queueIterator2;
        }
    }
}