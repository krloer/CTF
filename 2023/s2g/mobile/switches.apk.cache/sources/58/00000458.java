package com.badlogic.gdx.utils;

import java.util.Arrays;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public class IntSet {
    boolean hasZeroValue;
    private transient IntSetIterator iterator1;
    private transient IntSetIterator iterator2;
    int[] keyTable;
    private final float loadFactor;
    protected int mask;
    protected int shift;
    public int size;
    private int threshold;

    public IntSet() {
        this(51, 0.8f);
    }

    public IntSet(int initialCapacity) {
        this(initialCapacity, 0.8f);
    }

    public IntSet(int initialCapacity, float loadFactor) {
        if (loadFactor <= 0.0f || loadFactor >= 1.0f) {
            throw new IllegalArgumentException("loadFactor must be > 0 and < 1: " + loadFactor);
        }
        this.loadFactor = loadFactor;
        int tableSize = ObjectSet.tableSize(initialCapacity, loadFactor);
        this.threshold = (int) (tableSize * loadFactor);
        this.mask = tableSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        this.keyTable = new int[tableSize];
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public IntSet(com.badlogic.gdx.utils.IntSet r5) {
        /*
            r4 = this;
            int[] r0 = r5.keyTable
            int r0 = r0.length
            float r0 = (float) r0
            float r1 = r5.loadFactor
            float r0 = r0 * r1
            int r0 = (int) r0
            r4.<init>(r0, r1)
            int[] r0 = r5.keyTable
            int[] r1 = r4.keyTable
            int r2 = r0.length
            r3 = 0
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int r0 = r5.size
            r4.size = r0
            boolean r0 = r5.hasZeroValue
            r4.hasZeroValue = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.IntSet.<init>(com.badlogic.gdx.utils.IntSet):void");
    }

    protected int place(int item) {
        return (int) ((item * (-7046029254386353131L)) >>> this.shift);
    }

    private int locateKey(int key) {
        int[] keyTable = this.keyTable;
        int i = place(key);
        while (true) {
            int other = keyTable[i];
            if (other == 0) {
                return -(i + 1);
            }
            if (other == key) {
                return i;
            }
            i = (i + 1) & this.mask;
        }
    }

    public boolean add(int key) {
        if (key == 0) {
            if (this.hasZeroValue) {
                return false;
            }
            this.hasZeroValue = true;
            this.size++;
            return true;
        }
        int i = locateKey(key);
        if (i >= 0) {
            return false;
        }
        int[] iArr = this.keyTable;
        iArr[-(i + 1)] = key;
        int i2 = this.size + 1;
        this.size = i2;
        if (i2 >= this.threshold) {
            resize(iArr.length << 1);
        }
        return true;
    }

    public void addAll(IntArray array) {
        addAll(array.items, 0, array.size);
    }

    public void addAll(IntArray array, int offset, int length) {
        if (offset + length > array.size) {
            throw new IllegalArgumentException("offset + length must be <= size: " + offset + " + " + length + " <= " + array.size);
        }
        addAll(array.items, offset, length);
    }

    public void addAll(int... array) {
        addAll(array, 0, array.length);
    }

    public void addAll(int[] array, int offset, int length) {
        ensureCapacity(length);
        int i = offset;
        int n = i + length;
        while (i < n) {
            add(array[i]);
            i++;
        }
    }

    public void addAll(IntSet set) {
        ensureCapacity(set.size);
        if (set.hasZeroValue) {
            add(0);
        }
        int[] keyTable = set.keyTable;
        for (int key : keyTable) {
            if (key != 0) {
                add(key);
            }
        }
    }

    private void addResize(int key) {
        int[] keyTable = this.keyTable;
        int i = place(key);
        while (keyTable[i] != 0) {
            i = (i + 1) & this.mask;
        }
        keyTable[i] = key;
    }

    public boolean remove(int key) {
        if (key == 0) {
            if (!this.hasZeroValue) {
                return false;
            }
            this.hasZeroValue = false;
            this.size--;
            return true;
        }
        int i = locateKey(key);
        if (i < 0) {
            return false;
        }
        int[] keyTable = this.keyTable;
        int mask = this.mask;
        int next = (i + 1) & mask;
        while (true) {
            int key2 = keyTable[next];
            if (key2 != 0) {
                int placement = place(key2);
                if (((next - placement) & mask) > ((i - placement) & mask)) {
                    keyTable[i] = key2;
                    i = next;
                }
                next = (next + 1) & mask;
            } else {
                keyTable[i] = 0;
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
        int tableSize = ObjectSet.tableSize(maximumCapacity, this.loadFactor);
        if (this.keyTable.length > tableSize) {
            resize(tableSize);
        }
    }

    public void clear(int maximumCapacity) {
        int tableSize = ObjectSet.tableSize(maximumCapacity, this.loadFactor);
        if (this.keyTable.length <= tableSize) {
            clear();
            return;
        }
        this.size = 0;
        this.hasZeroValue = false;
        resize(tableSize);
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        this.size = 0;
        Arrays.fill(this.keyTable, 0);
        this.hasZeroValue = false;
    }

    public boolean contains(int key) {
        return key == 0 ? this.hasZeroValue : locateKey(key) >= 0;
    }

    public int first() {
        if (this.hasZeroValue) {
            return 0;
        }
        int[] keyTable = this.keyTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            if (keyTable[i] != 0) {
                return keyTable[i];
            }
        }
        throw new IllegalStateException("IntSet is empty.");
    }

    public void ensureCapacity(int additionalCapacity) {
        int tableSize = ObjectSet.tableSize(this.size + additionalCapacity, this.loadFactor);
        if (this.keyTable.length < tableSize) {
            resize(tableSize);
        }
    }

    private void resize(int newSize) {
        int oldCapacity = this.keyTable.length;
        this.threshold = (int) (newSize * this.loadFactor);
        this.mask = newSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        int[] oldKeyTable = this.keyTable;
        this.keyTable = new int[newSize];
        if (this.size > 0) {
            for (int i = 0; i < oldCapacity; i++) {
                int key = oldKeyTable[i];
                if (key != 0) {
                    addResize(key);
                }
            }
        }
    }

    public int hashCode() {
        int h = this.size;
        int[] keyTable = this.keyTable;
        for (int key : keyTable) {
            if (key != 0) {
                h += key;
            }
        }
        return h;
    }

    public boolean equals(Object obj) {
        if (obj instanceof IntSet) {
            IntSet other = (IntSet) obj;
            if (other.size == this.size && other.hasZeroValue == this.hasZeroValue) {
                int[] keyTable = this.keyTable;
                int n = keyTable.length;
                for (int i = 0; i < n; i++) {
                    if (keyTable[i] != 0 && !other.contains(keyTable[i])) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0040  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x002d -> B:16:0x002e). Please submit an issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public java.lang.String toString() {
        /*
            r5 = this;
            int r0 = r5.size
            if (r0 != 0) goto L7
            java.lang.String r0 = "[]"
            return r0
        L7:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r1 = 32
            r0.<init>(r1)
            r1 = 91
            r0.append(r1)
            int[] r1 = r5.keyTable
            int r2 = r1.length
            boolean r3 = r5.hasZeroValue
            if (r3 == 0) goto L20
            java.lang.String r3 = "0"
            r0.append(r3)
            goto L2e
        L20:
            int r3 = r2 + (-1)
            if (r2 <= 0) goto L2d
            r2 = r1[r3]
            if (r2 != 0) goto L2a
            r2 = r3
            goto L20
        L2a:
            r0.append(r2)
        L2d:
            r2 = r3
        L2e:
            int r3 = r2 + (-1)
            if (r2 <= 0) goto L40
            r2 = r1[r3]
            if (r2 != 0) goto L37
            goto L2d
        L37:
            java.lang.String r4 = ", "
            r0.append(r4)
            r0.append(r2)
            goto L2d
        L40:
            r2 = 93
            r0.append(r2)
            java.lang.String r2 = r0.toString()
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.IntSet.toString():java.lang.String");
    }

    public IntSetIterator iterator() {
        if (Collections.allocateIterators) {
            return new IntSetIterator(this);
        }
        if (this.iterator1 == null) {
            this.iterator1 = new IntSetIterator(this);
            this.iterator2 = new IntSetIterator(this);
        }
        if (!this.iterator1.valid) {
            this.iterator1.reset();
            IntSetIterator intSetIterator = this.iterator1;
            intSetIterator.valid = true;
            this.iterator2.valid = false;
            return intSetIterator;
        }
        this.iterator2.reset();
        IntSetIterator intSetIterator2 = this.iterator2;
        intSetIterator2.valid = true;
        this.iterator1.valid = false;
        return intSetIterator2;
    }

    public static IntSet with(int... array) {
        IntSet set = new IntSet();
        set.addAll(array);
        return set;
    }

    /* loaded from: classes.dex */
    public static class IntSetIterator {
        private static final int INDEX_ILLEGAL = -2;
        private static final int INDEX_ZERO = -1;
        int currentIndex;
        public boolean hasNext;
        int nextIndex;
        final IntSet set;
        boolean valid = true;

        public IntSetIterator(IntSet set) {
            this.set = set;
            reset();
        }

        public void reset() {
            this.currentIndex = INDEX_ILLEGAL;
            this.nextIndex = -1;
            if (this.set.hasZeroValue) {
                this.hasNext = true;
            } else {
                findNextIndex();
            }
        }

        void findNextIndex() {
            int[] keyTable = this.set.keyTable;
            int n = keyTable.length;
            do {
                int i = this.nextIndex + 1;
                this.nextIndex = i;
                if (i >= n) {
                    this.hasNext = false;
                    return;
                }
            } while (keyTable[this.nextIndex] == 0);
            this.hasNext = true;
        }

        public void remove() {
            int i = this.currentIndex;
            if (i == -1 && this.set.hasZeroValue) {
                this.set.hasZeroValue = false;
            } else if (i < 0) {
                throw new IllegalStateException("next must be called before remove.");
            } else {
                int[] keyTable = this.set.keyTable;
                int mask = this.set.mask;
                int next = (i + 1) & mask;
                while (true) {
                    int key = keyTable[next];
                    if (key == 0) {
                        break;
                    }
                    int placement = this.set.place(key);
                    if (((next - placement) & mask) > ((i - placement) & mask)) {
                        keyTable[i] = key;
                        i = next;
                    }
                    next = (next + 1) & mask;
                }
                keyTable[i] = 0;
                if (i != this.currentIndex) {
                    this.nextIndex--;
                }
            }
            this.currentIndex = INDEX_ILLEGAL;
            IntSet intSet = this.set;
            intSet.size--;
        }

        public int next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            int key = this.nextIndex == -1 ? 0 : this.set.keyTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return key;
        }

        public IntArray toArray() {
            IntArray array = new IntArray(true, this.set.size);
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }
}