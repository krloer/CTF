package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.MathUtils;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ObjectSet<T> implements Iterable<T> {
    private transient ObjectSetIterator iterator1;
    private transient ObjectSetIterator iterator2;
    T[] keyTable;
    float loadFactor;
    protected int mask;
    protected int shift;
    public int size;
    int threshold;

    public ObjectSet() {
        this(51, 0.8f);
    }

    public ObjectSet(int initialCapacity) {
        this(initialCapacity, 0.8f);
    }

    public ObjectSet(int initialCapacity, float loadFactor) {
        if (loadFactor <= 0.0f || loadFactor >= 1.0f) {
            throw new IllegalArgumentException("loadFactor must be > 0 and < 1: " + loadFactor);
        }
        this.loadFactor = loadFactor;
        int tableSize = tableSize(initialCapacity, loadFactor);
        this.threshold = (int) (tableSize * loadFactor);
        this.mask = tableSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        this.keyTable = (T[]) new Object[tableSize];
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public ObjectSet(com.badlogic.gdx.utils.ObjectSet<? extends T> r5) {
        /*
            r4 = this;
            T[] r0 = r5.keyTable
            int r0 = r0.length
            float r0 = (float) r0
            float r1 = r5.loadFactor
            float r0 = r0 * r1
            int r0 = (int) r0
            r4.<init>(r0, r1)
            T[] r0 = r5.keyTable
            T[] r1 = r4.keyTable
            int r2 = r0.length
            r3 = 0
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int r0 = r5.size
            r4.size = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.ObjectSet.<init>(com.badlogic.gdx.utils.ObjectSet):void");
    }

    protected int place(T item) {
        return (int) ((item.hashCode() * (-7046029254386353131L)) >>> this.shift);
    }

    int locateKey(T key) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null.");
        }
        T[] keyTable = this.keyTable;
        int i = place(key);
        while (true) {
            T other = keyTable[i];
            if (other == null) {
                return -(i + 1);
            }
            if (other.equals(key)) {
                return i;
            }
            i = (i + 1) & this.mask;
        }
    }

    public boolean add(T key) {
        int i = locateKey(key);
        if (i >= 0) {
            return false;
        }
        T[] tArr = this.keyTable;
        tArr[-(i + 1)] = key;
        int i2 = this.size + 1;
        this.size = i2;
        if (i2 >= this.threshold) {
            resize(tArr.length << 1);
        }
        return true;
    }

    public void addAll(Array<? extends T> array) {
        addAll(array.items, 0, array.size);
    }

    public void addAll(Array<? extends T> array, int offset, int length) {
        if (offset + length > array.size) {
            throw new IllegalArgumentException("offset + length must be <= size: " + offset + " + " + length + " <= " + array.size);
        }
        addAll(array.items, offset, length);
    }

    public boolean addAll(T... array) {
        return addAll(array, 0, array.length);
    }

    public boolean addAll(T[] array, int offset, int length) {
        ensureCapacity(length);
        int oldSize = this.size;
        int i = offset;
        int n = i + length;
        while (i < n) {
            add(array[i]);
            i++;
        }
        return oldSize != this.size;
    }

    public void addAll(ObjectSet<T> set) {
        ensureCapacity(set.size);
        T[] keyTable = set.keyTable;
        for (T key : keyTable) {
            if (key != null) {
                add(key);
            }
        }
    }

    private void addResize(T key) {
        T[] keyTable = this.keyTable;
        int i = place(key);
        while (keyTable[i] != null) {
            i = (i + 1) & this.mask;
        }
        keyTable[i] = key;
    }

    public boolean remove(T key) {
        int i = locateKey(key);
        if (i < 0) {
            return false;
        }
        T[] keyTable = this.keyTable;
        int mask = this.mask;
        int next = (i + 1) & mask;
        while (true) {
            T key2 = keyTable[next];
            if (key2 != null) {
                int placement = place(key2);
                if (((next - placement) & mask) > ((i - placement) & mask)) {
                    keyTable[i] = key2;
                    i = next;
                }
                next = (next + 1) & mask;
            } else {
                keyTable[i] = null;
                this.size--;
                return true;
            }
        }
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    public void shrink(int maximumCapacity) {
        if (maximumCapacity < 0) {
            throw new IllegalArgumentException("maximumCapacity must be >= 0: " + maximumCapacity);
        }
        int tableSize = tableSize(maximumCapacity, this.loadFactor);
        if (this.keyTable.length > tableSize) {
            resize(tableSize);
        }
    }

    public void clear(int maximumCapacity) {
        int tableSize = tableSize(maximumCapacity, this.loadFactor);
        if (this.keyTable.length <= tableSize) {
            clear();
            return;
        }
        this.size = 0;
        resize(tableSize);
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        this.size = 0;
        Arrays.fill(this.keyTable, (Object) null);
    }

    public boolean contains(T key) {
        return locateKey(key) >= 0;
    }

    public T get(T key) {
        int i = locateKey(key);
        if (i < 0) {
            return null;
        }
        return this.keyTable[i];
    }

    public T first() {
        T[] keyTable = this.keyTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            if (keyTable[i] != null) {
                return keyTable[i];
            }
        }
        throw new IllegalStateException("ObjectSet is empty.");
    }

    public void ensureCapacity(int additionalCapacity) {
        int tableSize = tableSize(this.size + additionalCapacity, this.loadFactor);
        if (this.keyTable.length < tableSize) {
            resize(tableSize);
        }
    }

    private void resize(int newSize) {
        int oldCapacity = this.keyTable.length;
        this.threshold = (int) (newSize * this.loadFactor);
        this.mask = newSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        T[] oldKeyTable = this.keyTable;
        this.keyTable = (T[]) new Object[newSize];
        if (this.size > 0) {
            for (int i = 0; i < oldCapacity; i++) {
                T key = oldKeyTable[i];
                if (key != null) {
                    addResize(key);
                }
            }
        }
    }

    public int hashCode() {
        int h = this.size;
        T[] keyTable = this.keyTable;
        for (T key : keyTable) {
            if (key != null) {
                h += key.hashCode();
            }
        }
        return h;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ObjectSet) {
            ObjectSet other = (ObjectSet) obj;
            if (other.size != this.size) {
                return false;
            }
            T[] keyTable = this.keyTable;
            int n = keyTable.length;
            for (int i = 0; i < n; i++) {
                if (keyTable[i] != null && !other.contains(keyTable[i])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public String toString() {
        return '{' + toString(", ") + '}';
    }

    public String toString(String separator) {
        int i;
        if (this.size == 0) {
            return BuildConfig.FLAVOR;
        }
        java.lang.StringBuilder buffer = new java.lang.StringBuilder(32);
        T[] keyTable = this.keyTable;
        int i2 = keyTable.length;
        while (true) {
            i = i2 - 1;
            if (i2 <= 0) {
                break;
            }
            T key = keyTable[i];
            if (key == null) {
                i2 = i;
            } else {
                buffer.append(key == this ? "(this)" : key);
            }
        }
        while (true) {
            int i3 = i - 1;
            if (i > 0) {
                T key2 = keyTable[i3];
                if (key2 != null) {
                    buffer.append(separator);
                    buffer.append(key2 == this ? "(this)" : key2);
                }
                i = i3;
            } else {
                return buffer.toString();
            }
        }
    }

    @Override // java.lang.Iterable
    public ObjectSetIterator<T> iterator() {
        if (Collections.allocateIterators) {
            return new ObjectSetIterator<>(this);
        }
        if (this.iterator1 == null) {
            this.iterator1 = new ObjectSetIterator(this);
            this.iterator2 = new ObjectSetIterator(this);
        }
        if (!this.iterator1.valid) {
            this.iterator1.reset();
            ObjectSetIterator<T> objectSetIterator = this.iterator1;
            objectSetIterator.valid = true;
            this.iterator2.valid = false;
            return objectSetIterator;
        }
        this.iterator2.reset();
        ObjectSetIterator<T> objectSetIterator2 = this.iterator2;
        objectSetIterator2.valid = true;
        this.iterator1.valid = false;
        return objectSetIterator2;
    }

    public static <T> ObjectSet<T> with(T... array) {
        ObjectSet<T> set = new ObjectSet<>();
        set.addAll(array);
        return set;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int tableSize(int capacity, float loadFactor) {
        if (capacity < 0) {
            throw new IllegalArgumentException("capacity must be >= 0: " + capacity);
        }
        int tableSize = MathUtils.nextPowerOfTwo(Math.max(2, (int) Math.ceil(capacity / loadFactor)));
        if (tableSize > 1073741824) {
            throw new IllegalArgumentException("The required capacity is too large: " + capacity);
        }
        return tableSize;
    }

    /* loaded from: classes.dex */
    public static class ObjectSetIterator<K> implements Iterable<K>, Iterator<K> {
        int currentIndex;
        public boolean hasNext;
        int nextIndex;
        final ObjectSet<K> set;
        boolean valid = true;

        public ObjectSetIterator(ObjectSet<K> set) {
            this.set = set;
            reset();
        }

        public void reset() {
            this.currentIndex = -1;
            this.nextIndex = -1;
            findNextIndex();
        }

        private void findNextIndex() {
            K[] keyTable = this.set.keyTable;
            int n = this.set.keyTable.length;
            do {
                int i = this.nextIndex + 1;
                this.nextIndex = i;
                if (i >= n) {
                    this.hasNext = false;
                    return;
                }
            } while (keyTable[this.nextIndex] == null);
            this.hasNext = true;
        }

        @Override // java.util.Iterator
        public void remove() {
            int i = this.currentIndex;
            if (i < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            K[] keyTable = this.set.keyTable;
            int mask = this.set.mask;
            int next = (i + 1) & mask;
            while (true) {
                K key = keyTable[next];
                if (key == null) {
                    break;
                }
                int placement = this.set.place(key);
                if (((next - placement) & mask) > ((i - placement) & mask)) {
                    keyTable[i] = key;
                    i = next;
                }
                next = (next + 1) & mask;
            }
            keyTable[i] = null;
            ObjectSet<K> objectSet = this.set;
            objectSet.size--;
            if (i != this.currentIndex) {
                this.nextIndex--;
            }
            this.currentIndex = -1;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            return this.hasNext;
        }

        @Override // java.util.Iterator
        public K next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K[] kArr = this.set.keyTable;
            int i = this.nextIndex;
            K key = kArr[i];
            this.currentIndex = i;
            findNextIndex();
            return key;
        }

        @Override // java.lang.Iterable
        public ObjectSetIterator<K> iterator() {
            return this;
        }

        public Array<K> toArray(Array<K> array) {
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }

        public Array<K> toArray() {
            return toArray(new Array<>(true, this.set.size));
        }
    }
}