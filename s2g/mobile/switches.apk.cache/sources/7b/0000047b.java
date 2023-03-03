package com.badlogic.gdx.utils;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ObjectIntMap<K> implements Iterable<Entry<K>> {
    transient Entries entries1;
    transient Entries entries2;
    K[] keyTable;
    transient Keys keys1;
    transient Keys keys2;
    float loadFactor;
    protected int mask;
    protected int shift;
    public int size;
    int threshold;
    int[] valueTable;
    transient Values values1;
    transient Values values2;

    public ObjectIntMap() {
        this(51, 0.8f);
    }

    public ObjectIntMap(int initialCapacity) {
        this(initialCapacity, 0.8f);
    }

    public ObjectIntMap(int initialCapacity, float loadFactor) {
        if (loadFactor <= 0.0f || loadFactor >= 1.0f) {
            throw new IllegalArgumentException("loadFactor must be > 0 and < 1: " + loadFactor);
        }
        this.loadFactor = loadFactor;
        int tableSize = ObjectSet.tableSize(initialCapacity, loadFactor);
        this.threshold = (int) (tableSize * loadFactor);
        this.mask = tableSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        this.keyTable = (K[]) new Object[tableSize];
        this.valueTable = new int[tableSize];
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public ObjectIntMap(com.badlogic.gdx.utils.ObjectIntMap<? extends K> r5) {
        /*
            r4 = this;
            K[] r0 = r5.keyTable
            int r0 = r0.length
            float r0 = (float) r0
            float r1 = r5.loadFactor
            float r0 = r0 * r1
            int r0 = (int) r0
            r4.<init>(r0, r1)
            K[] r0 = r5.keyTable
            K[] r1 = r4.keyTable
            int r2 = r0.length
            r3 = 0
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int[] r0 = r5.valueTable
            int[] r1 = r4.valueTable
            int r2 = r0.length
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int r0 = r5.size
            r4.size = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.ObjectIntMap.<init>(com.badlogic.gdx.utils.ObjectIntMap):void");
    }

    protected int place(K item) {
        return (int) ((item.hashCode() * (-7046029254386353131L)) >>> this.shift);
    }

    int locateKey(K key) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null.");
        }
        K[] keyTable = this.keyTable;
        int i = place(key);
        while (true) {
            K other = keyTable[i];
            if (other == null) {
                return -(i + 1);
            }
            if (other.equals(key)) {
                return i;
            }
            i = (i + 1) & this.mask;
        }
    }

    public void put(K key, int value) {
        int i = locateKey(key);
        if (i >= 0) {
            this.valueTable[i] = value;
            return;
        }
        int i2 = -(i + 1);
        K[] kArr = this.keyTable;
        kArr[i2] = key;
        this.valueTable[i2] = value;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(kArr.length << 1);
        }
    }

    public int put(K key, int value, int defaultValue) {
        int i = locateKey(key);
        if (i >= 0) {
            int[] iArr = this.valueTable;
            int oldValue = iArr[i];
            iArr[i] = value;
            return oldValue;
        }
        int i2 = -(i + 1);
        K[] kArr = this.keyTable;
        kArr[i2] = key;
        this.valueTable[i2] = value;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(kArr.length << 1);
        }
        return defaultValue;
    }

    public void putAll(ObjectIntMap<? extends K> map) {
        ensureCapacity(map.size);
        K[] keyTable = map.keyTable;
        int[] valueTable = map.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            K key = keyTable[i];
            if (key != null) {
                put(key, valueTable[i]);
            }
        }
    }

    private void putResize(K key, int value) {
        K[] keyTable = this.keyTable;
        int i = place(key);
        while (keyTable[i] != null) {
            i = (i + 1) & this.mask;
        }
        keyTable[i] = key;
        this.valueTable[i] = value;
    }

    public int get(K key, int defaultValue) {
        int i = locateKey(key);
        return i < 0 ? defaultValue : this.valueTable[i];
    }

    public int getAndIncrement(K key, int defaultValue, int increment) {
        int i = locateKey(key);
        if (i >= 0) {
            int[] iArr = this.valueTable;
            int oldValue = iArr[i];
            iArr[i] = iArr[i] + increment;
            return oldValue;
        }
        int i2 = -(i + 1);
        K[] kArr = this.keyTable;
        kArr[i2] = key;
        this.valueTable[i2] = defaultValue + increment;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(kArr.length << 1);
        }
        return defaultValue;
    }

    public int remove(K key, int defaultValue) {
        int i = locateKey(key);
        if (i < 0) {
            return defaultValue;
        }
        K[] keyTable = this.keyTable;
        int[] valueTable = this.valueTable;
        int oldValue = valueTable[i];
        int mask = this.mask;
        int next = (i + 1) & mask;
        while (true) {
            K key2 = keyTable[next];
            if (key2 != null) {
                int placement = place(key2);
                if (((next - placement) & mask) > ((i - placement) & mask)) {
                    keyTable[i] = key2;
                    valueTable[i] = valueTable[next];
                    i = next;
                }
                next = (next + 1) & mask;
            } else {
                keyTable[i] = null;
                this.size--;
                return oldValue;
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
        resize(tableSize);
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        this.size = 0;
        Arrays.fill(this.keyTable, (Object) null);
    }

    public boolean containsValue(int value) {
        K[] keyTable = this.keyTable;
        int[] valueTable = this.valueTable;
        for (int i = valueTable.length - 1; i >= 0; i--) {
            if (keyTable[i] != null && valueTable[i] == value) {
                return true;
            }
        }
        return false;
    }

    public boolean containsKey(K key) {
        return locateKey(key) >= 0;
    }

    public K findKey(int value) {
        K[] keyTable = this.keyTable;
        int[] valueTable = this.valueTable;
        for (int i = valueTable.length - 1; i >= 0; i--) {
            K key = keyTable[i];
            if (key != null && valueTable[i] == value) {
                return key;
            }
        }
        return null;
    }

    public void ensureCapacity(int additionalCapacity) {
        int tableSize = ObjectSet.tableSize(this.size + additionalCapacity, this.loadFactor);
        if (this.keyTable.length < tableSize) {
            resize(tableSize);
        }
    }

    final void resize(int newSize) {
        int oldCapacity = this.keyTable.length;
        this.threshold = (int) (newSize * this.loadFactor);
        this.mask = newSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        K[] oldKeyTable = this.keyTable;
        int[] oldValueTable = this.valueTable;
        this.keyTable = (K[]) new Object[newSize];
        this.valueTable = new int[newSize];
        if (this.size > 0) {
            for (int i = 0; i < oldCapacity; i++) {
                K key = oldKeyTable[i];
                if (key != null) {
                    putResize(key, oldValueTable[i]);
                }
            }
        }
    }

    public int hashCode() {
        int h = this.size;
        K[] keyTable = this.keyTable;
        int[] valueTable = this.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            K key = keyTable[i];
            if (key != null) {
                h += key.hashCode() + valueTable[i];
            }
        }
        return h;
    }

    public boolean equals(Object obj) {
        int otherValue;
        if (obj == this) {
            return true;
        }
        if (obj instanceof ObjectIntMap) {
            ObjectIntMap other = (ObjectIntMap) obj;
            if (other.size != this.size) {
                return false;
            }
            K[] keyTable = this.keyTable;
            int[] valueTable = this.valueTable;
            int n = keyTable.length;
            for (int i = 0; i < n; i++) {
                K key = keyTable[i];
                if (key != null && (((otherValue = other.get(key, 0)) == 0 && !other.containsKey(key)) || otherValue != valueTable[i])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public String toString(String separator) {
        return toString(separator, false);
    }

    public String toString() {
        return toString(", ", true);
    }

    private String toString(String separator, boolean braces) {
        int i;
        if (this.size == 0) {
            return braces ? "{}" : BuildConfig.FLAVOR;
        }
        java.lang.StringBuilder buffer = new java.lang.StringBuilder(32);
        if (braces) {
            buffer.append('{');
        }
        K[] keyTable = this.keyTable;
        int[] valueTable = this.valueTable;
        int i2 = keyTable.length;
        while (true) {
            i = i2 - 1;
            if (i2 > 0) {
                K key = keyTable[i];
                if (key != null) {
                    buffer.append(key);
                    buffer.append('=');
                    buffer.append(valueTable[i]);
                    break;
                }
                i2 = i;
            } else {
                break;
            }
        }
        while (true) {
            int i3 = i - 1;
            if (i <= 0) {
                break;
            }
            K key2 = keyTable[i3];
            if (key2 != null) {
                buffer.append(separator);
                buffer.append(key2);
                buffer.append('=');
                buffer.append(valueTable[i3]);
            }
            i = i3;
        }
        if (braces) {
            buffer.append('}');
        }
        return buffer.toString();
    }

    @Override // java.lang.Iterable
    public Entries<K> iterator() {
        return entries();
    }

    public Entries<K> entries() {
        if (Collections.allocateIterators) {
            return new Entries<>(this);
        }
        if (this.entries1 == null) {
            this.entries1 = new Entries(this);
            this.entries2 = new Entries(this);
        }
        if (!this.entries1.valid) {
            this.entries1.reset();
            Entries<K> entries = this.entries1;
            entries.valid = true;
            this.entries2.valid = false;
            return entries;
        }
        this.entries2.reset();
        Entries<K> entries2 = this.entries2;
        entries2.valid = true;
        this.entries1.valid = false;
        return entries2;
    }

    public Values values() {
        if (Collections.allocateIterators) {
            return new Values(this);
        }
        if (this.values1 == null) {
            this.values1 = new Values(this);
            this.values2 = new Values(this);
        }
        if (!this.values1.valid) {
            this.values1.reset();
            Values values = this.values1;
            values.valid = true;
            this.values2.valid = false;
            return values;
        }
        this.values2.reset();
        Values values2 = this.values2;
        values2.valid = true;
        this.values1.valid = false;
        return values2;
    }

    public Keys<K> keys() {
        if (Collections.allocateIterators) {
            return new Keys<>(this);
        }
        if (this.keys1 == null) {
            this.keys1 = new Keys(this);
            this.keys2 = new Keys(this);
        }
        if (!this.keys1.valid) {
            this.keys1.reset();
            Keys<K> keys = this.keys1;
            keys.valid = true;
            this.keys2.valid = false;
            return keys;
        }
        this.keys2.reset();
        Keys<K> keys2 = this.keys2;
        keys2.valid = true;
        this.keys1.valid = false;
        return keys2;
    }

    /* loaded from: classes.dex */
    public static class Entry<K> {
        public K key;
        public int value;

        public String toString() {
            return this.key + "=" + this.value;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class MapIterator<K> {
        int currentIndex;
        public boolean hasNext;
        final ObjectIntMap<K> map;
        int nextIndex;
        boolean valid = true;

        public MapIterator(ObjectIntMap<K> map) {
            this.map = map;
            reset();
        }

        public void reset() {
            this.currentIndex = -1;
            this.nextIndex = -1;
            findNextIndex();
        }

        void findNextIndex() {
            K[] keyTable = this.map.keyTable;
            int n = keyTable.length;
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

        public void remove() {
            int i = this.currentIndex;
            if (i < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            K[] keyTable = this.map.keyTable;
            int[] valueTable = this.map.valueTable;
            int mask = this.map.mask;
            int next = (i + 1) & mask;
            while (true) {
                K key = keyTable[next];
                if (key == null) {
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
            keyTable[i] = null;
            ObjectIntMap<K> objectIntMap = this.map;
            objectIntMap.size--;
            if (i != this.currentIndex) {
                this.nextIndex--;
            }
            this.currentIndex = -1;
        }
    }

    /* loaded from: classes.dex */
    public static class Entries<K> extends MapIterator<K> implements Iterable<Entry<K>>, Iterator<Entry<K>> {
        Entry<K> entry;

        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Entries(ObjectIntMap<K> map) {
            super(map);
            this.entry = new Entry<>();
        }

        @Override // java.util.Iterator
        public Entry<K> next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K[] keyTable = this.map.keyTable;
            this.entry.key = keyTable[this.nextIndex];
            this.entry.value = this.map.valueTable[this.nextIndex];
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
        public Entries<K> iterator() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static class Values extends MapIterator<Object> {
        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Values(ObjectIntMap<?> map) {
            super(map);
        }

        public boolean hasNext() {
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            return this.hasNext;
        }

        public int next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            int value = this.map.valueTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return value;
        }

        public Values iterator() {
            return this;
        }

        public IntArray toArray() {
            IntArray array = new IntArray(true, this.map.size);
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }

        public IntArray toArray(IntArray array) {
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }

    /* loaded from: classes.dex */
    public static class Keys<K> extends MapIterator<K> implements Iterable<K>, Iterator<K> {
        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.ObjectIntMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Keys(ObjectIntMap<K> map) {
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
        public K next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K key = this.map.keyTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return key;
        }

        @Override // java.lang.Iterable
        public Keys<K> iterator() {
            return this;
        }

        public Array<K> toArray() {
            return toArray(new Array<>(true, this.map.size));
        }

        public Array<K> toArray(Array<K> array) {
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }
}