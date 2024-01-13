package com.badlogic.gdx.utils;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public class LongMap<V> implements Iterable<Entry<V>> {
    private transient Entries entries1;
    private transient Entries entries2;
    boolean hasZeroValue;
    long[] keyTable;
    private transient Keys keys1;
    private transient Keys keys2;
    private final float loadFactor;
    protected int mask;
    protected int shift;
    public int size;
    private int threshold;
    V[] valueTable;
    private transient Values values1;
    private transient Values values2;
    V zeroValue;

    public LongMap() {
        this(51, 0.8f);
    }

    public LongMap(int initialCapacity) {
        this(initialCapacity, 0.8f);
    }

    public LongMap(int initialCapacity, float loadFactor) {
        if (loadFactor <= 0.0f || loadFactor >= 1.0f) {
            throw new IllegalArgumentException("loadFactor must be > 0 and < 1: " + loadFactor);
        }
        this.loadFactor = loadFactor;
        int tableSize = ObjectSet.tableSize(initialCapacity, loadFactor);
        this.threshold = (int) (tableSize * loadFactor);
        this.mask = tableSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        this.keyTable = new long[tableSize];
        this.valueTable = (V[]) new Object[tableSize];
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public LongMap(com.badlogic.gdx.utils.LongMap<? extends V> r5) {
        /*
            r4 = this;
            long[] r0 = r5.keyTable
            int r0 = r0.length
            float r0 = (float) r0
            float r1 = r5.loadFactor
            float r0 = r0 * r1
            int r0 = (int) r0
            r4.<init>(r0, r1)
            long[] r0 = r5.keyTable
            long[] r1 = r4.keyTable
            int r2 = r0.length
            r3 = 0
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            V[] r0 = r5.valueTable
            V[] r1 = r4.valueTable
            int r2 = r0.length
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int r0 = r5.size
            r4.size = r0
            V r0 = r5.zeroValue
            r4.zeroValue = r0
            boolean r0 = r5.hasZeroValue
            r4.hasZeroValue = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.LongMap.<init>(com.badlogic.gdx.utils.LongMap):void");
    }

    protected int place(long item) {
        return (int) ((((item >>> 32) ^ item) * (-7046029254386353131L)) >>> this.shift);
    }

    private int locateKey(long key) {
        long[] keyTable = this.keyTable;
        int i = place(key);
        while (true) {
            long other = keyTable[i];
            if (other == 0) {
                return -(i + 1);
            }
            if (other == key) {
                return i;
            }
            i = (i + 1) & this.mask;
        }
    }

    public V put(long key, V value) {
        if (key == 0) {
            V oldValue = this.zeroValue;
            this.zeroValue = value;
            if (!this.hasZeroValue) {
                this.hasZeroValue = true;
                this.size++;
            }
            return oldValue;
        }
        int i = locateKey(key);
        if (i >= 0) {
            V[] vArr = this.valueTable;
            V oldValue2 = vArr[i];
            vArr[i] = value;
            return oldValue2;
        }
        int i2 = -(i + 1);
        long[] jArr = this.keyTable;
        jArr[i2] = key;
        this.valueTable[i2] = value;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(jArr.length << 1);
            return null;
        }
        return null;
    }

    public void putAll(LongMap<? extends V> map) {
        ensureCapacity(map.size);
        if (map.hasZeroValue) {
            put(0L, map.zeroValue);
        }
        long[] keyTable = map.keyTable;
        V[] valueTable = map.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            long key = keyTable[i];
            if (key != 0) {
                put(key, valueTable[i]);
            }
        }
    }

    private void putResize(long key, V value) {
        long[] keyTable = this.keyTable;
        int i = place(key);
        while (keyTable[i] != 0) {
            i = (i + 1) & this.mask;
        }
        keyTable[i] = key;
        this.valueTable[i] = value;
    }

    public V get(long key) {
        if (key == 0) {
            if (this.hasZeroValue) {
                return this.zeroValue;
            }
            return null;
        }
        int i = locateKey(key);
        if (i >= 0) {
            return this.valueTable[i];
        }
        return null;
    }

    public V get(long key, V defaultValue) {
        if (key == 0) {
            return this.hasZeroValue ? this.zeroValue : defaultValue;
        }
        int i = locateKey(key);
        return i >= 0 ? this.valueTable[i] : defaultValue;
    }

    public V remove(long key) {
        if (key == 0) {
            if (this.hasZeroValue) {
                this.hasZeroValue = false;
                V oldValue = this.zeroValue;
                this.zeroValue = null;
                this.size--;
                return oldValue;
            }
            return null;
        }
        int i = locateKey(key);
        if (i < 0) {
            return null;
        }
        long[] keyTable = this.keyTable;
        V[] valueTable = this.valueTable;
        V oldValue2 = valueTable[i];
        int mask = this.mask;
        int next = (i + 1) & mask;
        while (true) {
            long key2 = keyTable[next];
            if (key2 != 0) {
                int placement = place(key2);
                if (((next - placement) & mask) > ((i - placement) & mask)) {
                    keyTable[i] = key2;
                    valueTable[i] = valueTable[next];
                    i = next;
                }
                next = (next + 1) & mask;
            } else {
                keyTable[i] = 0;
                valueTable[i] = null;
                this.size--;
                return oldValue2;
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
        this.zeroValue = null;
        resize(tableSize);
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        this.size = 0;
        Arrays.fill(this.keyTable, 0L);
        Arrays.fill(this.valueTable, (Object) null);
        this.zeroValue = null;
        this.hasZeroValue = false;
    }

    public boolean containsValue(Object value, boolean identity) {
        V[] valueTable = this.valueTable;
        if (value == null) {
            if (this.hasZeroValue && this.zeroValue == null) {
                return true;
            }
            long[] keyTable = this.keyTable;
            for (int i = valueTable.length - 1; i >= 0; i--) {
                if (keyTable[i] != 0 && valueTable[i] == null) {
                    return true;
                }
            }
            return false;
        } else if (identity) {
            if (value == this.zeroValue) {
                return true;
            }
            for (int i2 = valueTable.length - 1; i2 >= 0; i2--) {
                if (valueTable[i2] == value) {
                    return true;
                }
            }
            return false;
        } else if (!this.hasZeroValue || !value.equals(this.zeroValue)) {
            for (int i3 = valueTable.length - 1; i3 >= 0; i3--) {
                if (value.equals(valueTable[i3])) {
                    return true;
                }
            }
            return false;
        } else {
            return true;
        }
    }

    public boolean containsKey(long key) {
        return key == 0 ? this.hasZeroValue : locateKey(key) >= 0;
    }

    public long findKey(Object value, boolean identity, long notFound) {
        V[] valueTable = this.valueTable;
        if (value == null) {
            if (this.hasZeroValue && this.zeroValue == null) {
                return 0L;
            }
            long[] keyTable = this.keyTable;
            for (int i = valueTable.length - 1; i >= 0; i--) {
                if (keyTable[i] != 0 && valueTable[i] == null) {
                    return keyTable[i];
                }
            }
        } else if (identity) {
            if (value == this.zeroValue) {
                return 0L;
            }
            for (int i2 = valueTable.length - 1; i2 >= 0; i2--) {
                if (valueTable[i2] == value) {
                    return this.keyTable[i2];
                }
            }
        } else if (this.hasZeroValue && value.equals(this.zeroValue)) {
            return 0L;
        } else {
            for (int i3 = valueTable.length - 1; i3 >= 0; i3--) {
                if (value.equals(valueTable[i3])) {
                    return this.keyTable[i3];
                }
            }
        }
        return notFound;
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
        long[] oldKeyTable = this.keyTable;
        V[] oldValueTable = this.valueTable;
        this.keyTable = new long[newSize];
        this.valueTable = (V[]) new Object[newSize];
        if (this.size > 0) {
            for (int i = 0; i < oldCapacity; i++) {
                long key = oldKeyTable[i];
                if (key != 0) {
                    putResize(key, oldValueTable[i]);
                }
            }
        }
    }

    public int hashCode() {
        V v;
        int h = this.size;
        if (this.hasZeroValue && (v = this.zeroValue) != null) {
            h += v.hashCode();
        }
        long[] keyTable = this.keyTable;
        V[] valueTable = this.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            long key = keyTable[i];
            if (key != 0) {
                h = (int) (h + (31 * key));
                V value = valueTable[i];
                if (value != null) {
                    h += value.hashCode();
                }
            }
        }
        return h;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof LongMap) {
            LongMap other = (LongMap) obj;
            if (other.size != this.size) {
                return false;
            }
            boolean z = other.hasZeroValue;
            boolean z2 = this.hasZeroValue;
            if (z != z2) {
                return false;
            }
            if (z2) {
                V v = other.zeroValue;
                if (v == null) {
                    if (this.zeroValue != null) {
                        return false;
                    }
                } else if (!v.equals(this.zeroValue)) {
                    return false;
                }
            }
            long[] keyTable = this.keyTable;
            V[] valueTable = this.valueTable;
            int n = keyTable.length;
            for (int i = 0; i < n; i++) {
                long key = keyTable[i];
                if (key != 0) {
                    V value = valueTable[i];
                    if (value == null) {
                        if (other.get(key, ObjectMap.dummy) != null) {
                            return false;
                        }
                    } else if (!value.equals(other.get(key))) {
                        return false;
                    }
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean equalsIdentity(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof LongMap) {
            LongMap other = (LongMap) obj;
            if (other.size != this.size) {
                return false;
            }
            boolean z = other.hasZeroValue;
            boolean z2 = this.hasZeroValue;
            if (z != z2) {
                return false;
            }
            if (!z2 || this.zeroValue == other.zeroValue) {
                long[] keyTable = this.keyTable;
                V[] valueTable = this.valueTable;
                int n = keyTable.length;
                for (int i = 0; i < n; i++) {
                    long key = keyTable[i];
                    if (key != 0 && valueTable[i] != other.get(key, ObjectMap.dummy)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005f  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x0042 -> B:16:0x0043). Please submit an issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public java.lang.String toString() {
        /*
            r10 = this;
            int r0 = r10.size
            if (r0 != 0) goto L7
            java.lang.String r0 = "[]"
            return r0
        L7:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r1 = 32
            r0.<init>(r1)
            r1 = 91
            r0.append(r1)
            long[] r1 = r10.keyTable
            V[] r2 = r10.valueTable
            int r3 = r1.length
            boolean r4 = r10.hasZeroValue
            r5 = 61
            r6 = 0
            if (r4 == 0) goto L2b
            java.lang.String r4 = "0="
            r0.append(r4)
            V r4 = r10.zeroValue
            r0.append(r4)
            goto L43
        L2b:
            int r4 = r3 + (-1)
            if (r3 <= 0) goto L42
            r8 = r1[r4]
            int r3 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r3 != 0) goto L37
            r3 = r4
            goto L2b
        L37:
            r0.append(r8)
            r0.append(r5)
            r3 = r2[r4]
            r0.append(r3)
        L42:
            r3 = r4
        L43:
            int r4 = r3 + (-1)
            if (r3 <= 0) goto L5f
            r8 = r1[r4]
            int r3 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r3 != 0) goto L4e
            goto L42
        L4e:
            java.lang.String r3 = ", "
            r0.append(r3)
            r0.append(r8)
            r0.append(r5)
            r3 = r2[r4]
            r0.append(r3)
            goto L42
        L5f:
            r3 = 93
            r0.append(r3)
            java.lang.String r3 = r0.toString()
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.LongMap.toString():java.lang.String");
    }

    @Override // java.lang.Iterable
    public Iterator<Entry<V>> iterator() {
        return entries();
    }

    public Entries<V> entries() {
        if (Collections.allocateIterators) {
            return new Entries<>(this);
        }
        if (this.entries1 == null) {
            this.entries1 = new Entries(this);
            this.entries2 = new Entries(this);
        }
        if (!this.entries1.valid) {
            this.entries1.reset();
            Entries<V> entries = this.entries1;
            entries.valid = true;
            this.entries2.valid = false;
            return entries;
        }
        this.entries2.reset();
        Entries<V> entries2 = this.entries2;
        entries2.valid = true;
        this.entries1.valid = false;
        return entries2;
    }

    public Values<V> values() {
        if (Collections.allocateIterators) {
            return new Values<>(this);
        }
        if (this.values1 == null) {
            this.values1 = new Values(this);
            this.values2 = new Values(this);
        }
        if (!this.values1.valid) {
            this.values1.reset();
            Values<V> values = this.values1;
            values.valid = true;
            this.values2.valid = false;
            return values;
        }
        this.values2.reset();
        Values<V> values2 = this.values2;
        values2.valid = true;
        this.values1.valid = false;
        return values2;
    }

    public Keys keys() {
        if (Collections.allocateIterators) {
            return new Keys(this);
        }
        if (this.keys1 == null) {
            this.keys1 = new Keys(this);
            this.keys2 = new Keys(this);
        }
        if (!this.keys1.valid) {
            this.keys1.reset();
            Keys keys = this.keys1;
            keys.valid = true;
            this.keys2.valid = false;
            return keys;
        }
        this.keys2.reset();
        Keys keys2 = this.keys2;
        keys2.valid = true;
        this.keys1.valid = false;
        return keys2;
    }

    /* loaded from: classes.dex */
    public static class Entry<V> {
        public long key;
        public V value;

        public String toString() {
            return this.key + "=" + this.value;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class MapIterator<V> {
        private static final int INDEX_ILLEGAL = -2;
        static final int INDEX_ZERO = -1;
        int currentIndex;
        public boolean hasNext;
        final LongMap<V> map;
        int nextIndex;
        boolean valid = true;

        public MapIterator(LongMap<V> map) {
            this.map = map;
            reset();
        }

        public void reset() {
            this.currentIndex = INDEX_ILLEGAL;
            this.nextIndex = -1;
            if (this.map.hasZeroValue) {
                this.hasNext = true;
            } else {
                findNextIndex();
            }
        }

        void findNextIndex() {
            long[] keyTable = this.map.keyTable;
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
            if (i == -1 && this.map.hasZeroValue) {
                LongMap<V> longMap = this.map;
                longMap.hasZeroValue = false;
                longMap.zeroValue = null;
            } else if (i < 0) {
                throw new IllegalStateException("next must be called before remove.");
            } else {
                long[] keyTable = this.map.keyTable;
                V[] valueTable = this.map.valueTable;
                int mask = this.map.mask;
                int next = (i + 1) & mask;
                while (true) {
                    long key = keyTable[next];
                    if (key == 0) {
                        break;
                    }
                    int placement = this.map.place(key);
                    if (((next - placement) & mask) > ((i - placement) & mask)) {
                        keyTable[i] = key;
                        valueTable[i] = valueTable[next];
                        i = next;
                    }
                    next = (next + 1) & mask;
                }
                keyTable[i] = 0;
                valueTable[i] = null;
                if (i != this.currentIndex) {
                    this.nextIndex--;
                }
            }
            this.currentIndex = INDEX_ILLEGAL;
            LongMap<V> longMap2 = this.map;
            longMap2.size--;
        }
    }

    /* loaded from: classes.dex */
    public static class Entries<V> extends MapIterator<V> implements Iterable<Entry<V>>, Iterator<Entry<V>> {
        private final Entry<V> entry;

        @Override // com.badlogic.gdx.utils.LongMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.LongMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Entries(LongMap map) {
            super(map);
            this.entry = new Entry<>();
        }

        @Override // java.util.Iterator
        public Entry<V> next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            long[] keyTable = this.map.keyTable;
            if (this.nextIndex == -1) {
                Entry<V> entry = this.entry;
                entry.key = 0L;
                entry.value = this.map.zeroValue;
            } else {
                this.entry.key = keyTable[this.nextIndex];
                this.entry.value = this.map.valueTable[this.nextIndex];
            }
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return this.entry;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            return this.hasNext;
        }

        @Override // java.lang.Iterable
        public Iterator<Entry<V>> iterator() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static class Values<V> extends MapIterator<V> implements Iterable<V>, Iterator<V> {
        @Override // com.badlogic.gdx.utils.LongMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.LongMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Values(LongMap<V> map) {
            super(map);
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            return this.hasNext;
        }

        @Override // java.util.Iterator
        public V next() {
            V value;
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            if (this.nextIndex == -1) {
                value = this.map.zeroValue;
            } else {
                value = this.map.valueTable[this.nextIndex];
            }
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return value;
        }

        @Override // java.lang.Iterable
        public Iterator<V> iterator() {
            return this;
        }

        public Array<V> toArray() {
            Array array = new Array(true, this.map.size);
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }

    /* loaded from: classes.dex */
    public static class Keys extends MapIterator {
        @Override // com.badlogic.gdx.utils.LongMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.LongMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Keys(LongMap map) {
            super(map);
        }

        public long next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            long key = this.nextIndex == -1 ? 0L : this.map.keyTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return key;
        }

        public LongArray toArray() {
            LongArray array = new LongArray(true, this.map.size);
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }

        public LongArray toArray(LongArray array) {
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }
}