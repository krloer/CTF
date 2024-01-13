package com.badlogic.gdx.utils;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public class IntFloatMap implements Iterable<Entry> {
    private transient Entries entries1;
    private transient Entries entries2;
    boolean hasZeroValue;
    int[] keyTable;
    private transient Keys keys1;
    private transient Keys keys2;
    private final float loadFactor;
    protected int mask;
    protected int shift;
    public int size;
    private int threshold;
    float[] valueTable;
    private transient Values values1;
    private transient Values values2;
    float zeroValue;

    public IntFloatMap() {
        this(51, 0.8f);
    }

    public IntFloatMap(int initialCapacity) {
        this(initialCapacity, 0.8f);
    }

    public IntFloatMap(int initialCapacity, float loadFactor) {
        if (loadFactor <= 0.0f || loadFactor >= 1.0f) {
            throw new IllegalArgumentException("loadFactor must be > 0 and < 1: " + loadFactor);
        }
        this.loadFactor = loadFactor;
        int tableSize = ObjectSet.tableSize(initialCapacity, loadFactor);
        this.threshold = (int) (tableSize * loadFactor);
        this.mask = tableSize - 1;
        this.shift = Long.numberOfLeadingZeros(this.mask);
        this.keyTable = new int[tableSize];
        this.valueTable = new float[tableSize];
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public IntFloatMap(com.badlogic.gdx.utils.IntFloatMap r5) {
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
            float[] r0 = r5.valueTable
            float[] r1 = r4.valueTable
            int r2 = r0.length
            java.lang.System.arraycopy(r0, r3, r1, r3, r2)
            int r0 = r5.size
            r4.size = r0
            float r0 = r5.zeroValue
            r4.zeroValue = r0
            boolean r0 = r5.hasZeroValue
            r4.hasZeroValue = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.IntFloatMap.<init>(com.badlogic.gdx.utils.IntFloatMap):void");
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

    public void put(int key, float value) {
        if (key == 0) {
            this.zeroValue = value;
            if (!this.hasZeroValue) {
                this.hasZeroValue = true;
                this.size++;
                return;
            }
            return;
        }
        int i = locateKey(key);
        if (i >= 0) {
            this.valueTable[i] = value;
            return;
        }
        int i2 = -(i + 1);
        int[] iArr = this.keyTable;
        iArr[i2] = key;
        this.valueTable[i2] = value;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(iArr.length << 1);
        }
    }

    public float put(int key, float value, float defaultValue) {
        if (key == 0) {
            float oldValue = this.zeroValue;
            this.zeroValue = value;
            if (!this.hasZeroValue) {
                this.hasZeroValue = true;
                this.size++;
                return defaultValue;
            }
            return oldValue;
        }
        int i = locateKey(key);
        if (i >= 0) {
            float[] fArr = this.valueTable;
            float oldValue2 = fArr[i];
            fArr[i] = value;
            return oldValue2;
        }
        int i2 = -(i + 1);
        int[] iArr = this.keyTable;
        iArr[i2] = key;
        this.valueTable[i2] = value;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(iArr.length << 1);
        }
        return defaultValue;
    }

    public void putAll(IntFloatMap map) {
        ensureCapacity(map.size);
        if (map.hasZeroValue) {
            put(0, map.zeroValue);
        }
        int[] keyTable = map.keyTable;
        float[] valueTable = map.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            int key = keyTable[i];
            if (key != 0) {
                put(key, valueTable[i]);
            }
        }
    }

    private void putResize(int key, float value) {
        int[] keyTable = this.keyTable;
        int i = place(key);
        while (keyTable[i] != 0) {
            i = (i + 1) & this.mask;
        }
        keyTable[i] = key;
        this.valueTable[i] = value;
    }

    public float get(int key, float defaultValue) {
        if (key == 0) {
            return this.hasZeroValue ? this.zeroValue : defaultValue;
        }
        int i = locateKey(key);
        return i >= 0 ? this.valueTable[i] : defaultValue;
    }

    public float getAndIncrement(int key, float defaultValue, float increment) {
        if (key == 0) {
            if (!this.hasZeroValue) {
                this.hasZeroValue = true;
                this.zeroValue = defaultValue + increment;
                this.size++;
                return defaultValue;
            }
            float oldValue = this.zeroValue;
            this.zeroValue += increment;
            return oldValue;
        }
        int i = locateKey(key);
        if (i >= 0) {
            float[] fArr = this.valueTable;
            float oldValue2 = fArr[i];
            fArr[i] = fArr[i] + increment;
            return oldValue2;
        }
        int i2 = -(i + 1);
        int[] iArr = this.keyTable;
        iArr[i2] = key;
        this.valueTable[i2] = defaultValue + increment;
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(iArr.length << 1);
        }
        return defaultValue;
    }

    public float remove(int key, float defaultValue) {
        if (key == 0) {
            if (this.hasZeroValue) {
                this.hasZeroValue = false;
                this.size--;
                return this.zeroValue;
            }
            return defaultValue;
        }
        int i = locateKey(key);
        if (i < 0) {
            return defaultValue;
        }
        int[] keyTable = this.keyTable;
        float[] valueTable = this.valueTable;
        float oldValue = valueTable[i];
        int mask = this.mask;
        int next = (i + 1) & mask;
        while (true) {
            int key2 = keyTable[next];
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
        this.hasZeroValue = false;
        resize(tableSize);
    }

    public void clear() {
        if (this.size == 0) {
            return;
        }
        Arrays.fill(this.keyTable, 0);
        this.size = 0;
        this.hasZeroValue = false;
    }

    public boolean containsValue(float value) {
        if (this.hasZeroValue && this.zeroValue == value) {
            return true;
        }
        int[] keyTable = this.keyTable;
        float[] valueTable = this.valueTable;
        for (int i = valueTable.length - 1; i >= 0; i--) {
            if (keyTable[i] != 0 && valueTable[i] == value) {
                return true;
            }
        }
        return false;
    }

    public boolean containsValue(float value, float epsilon) {
        if (!this.hasZeroValue || Math.abs(this.zeroValue - value) > epsilon) {
            int[] keyTable = this.keyTable;
            float[] valueTable = this.valueTable;
            for (int i = valueTable.length - 1; i >= 0; i--) {
                if (keyTable[i] != 0 && Math.abs(valueTable[i] - value) <= epsilon) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    public boolean containsKey(int key) {
        return key == 0 ? this.hasZeroValue : locateKey(key) >= 0;
    }

    public int findKey(float value, int notFound) {
        if (this.hasZeroValue && this.zeroValue == value) {
            return 0;
        }
        int[] keyTable = this.keyTable;
        float[] valueTable = this.valueTable;
        for (int i = valueTable.length - 1; i >= 0; i--) {
            if (keyTable[i] != 0 && valueTable[i] == value) {
                return keyTable[i];
            }
        }
        return notFound;
    }

    public int findKey(float value, float epsilon, int notFound) {
        if (!this.hasZeroValue || Math.abs(this.zeroValue - value) > epsilon) {
            int[] keyTable = this.keyTable;
            float[] valueTable = this.valueTable;
            for (int i = valueTable.length - 1; i >= 0; i--) {
                if (keyTable[i] != 0 && Math.abs(valueTable[i] - value) <= epsilon) {
                    return keyTable[i];
                }
            }
            return notFound;
        }
        return 0;
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
        float[] oldValueTable = this.valueTable;
        this.keyTable = new int[newSize];
        this.valueTable = new float[newSize];
        if (this.size > 0) {
            for (int i = 0; i < oldCapacity; i++) {
                int key = oldKeyTable[i];
                if (key != 0) {
                    putResize(key, oldValueTable[i]);
                }
            }
        }
    }

    public int hashCode() {
        int h = this.size;
        if (this.hasZeroValue) {
            h += NumberUtils.floatToRawIntBits(this.zeroValue);
        }
        int[] keyTable = this.keyTable;
        float[] valueTable = this.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            int key = keyTable[i];
            if (key != 0) {
                h += (key * 31) + NumberUtils.floatToRawIntBits(valueTable[i]);
            }
        }
        return h;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof IntFloatMap) {
            IntFloatMap other = (IntFloatMap) obj;
            if (other.size != this.size) {
                return false;
            }
            boolean z = other.hasZeroValue;
            boolean z2 = this.hasZeroValue;
            if (z != z2) {
                return false;
            }
            if (!z2 || other.zeroValue == this.zeroValue) {
                int[] keyTable = this.keyTable;
                float[] valueTable = this.valueTable;
                int n = keyTable.length;
                for (int i = 0; i < n; i++) {
                    int key = keyTable[i];
                    if (key != 0) {
                        float otherValue = other.get(key, 0.0f);
                        if ((otherValue == 0.0f && !other.containsKey(key)) || otherValue != valueTable[i]) {
                            return false;
                        }
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0059  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x003e -> B:16:0x003f). Please submit an issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public java.lang.String toString() {
        /*
            r7 = this;
            int r0 = r7.size
            if (r0 != 0) goto L7
            java.lang.String r0 = "[]"
            return r0
        L7:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r1 = 32
            r0.<init>(r1)
            r1 = 91
            r0.append(r1)
            int[] r1 = r7.keyTable
            float[] r2 = r7.valueTable
            int r3 = r1.length
            boolean r4 = r7.hasZeroValue
            r5 = 61
            if (r4 == 0) goto L29
            java.lang.String r4 = "0="
            r0.append(r4)
            float r4 = r7.zeroValue
            r0.append(r4)
            goto L3f
        L29:
            int r4 = r3 + (-1)
            if (r3 <= 0) goto L3e
            r3 = r1[r4]
            if (r3 != 0) goto L33
            r3 = r4
            goto L29
        L33:
            r0.append(r3)
            r0.append(r5)
            r6 = r2[r4]
            r0.append(r6)
        L3e:
            r3 = r4
        L3f:
            int r4 = r3 + (-1)
            if (r3 <= 0) goto L59
            r3 = r1[r4]
            if (r3 != 0) goto L48
            goto L3e
        L48:
            java.lang.String r6 = ", "
            r0.append(r6)
            r0.append(r3)
            r0.append(r5)
            r6 = r2[r4]
            r0.append(r6)
            goto L3e
        L59:
            r3 = 93
            r0.append(r3)
            java.lang.String r3 = r0.toString()
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.utils.IntFloatMap.toString():java.lang.String");
    }

    @Override // java.lang.Iterable
    public Iterator<Entry> iterator() {
        return entries();
    }

    public Entries entries() {
        if (Collections.allocateIterators) {
            return new Entries(this);
        }
        if (this.entries1 == null) {
            this.entries1 = new Entries(this);
            this.entries2 = new Entries(this);
        }
        if (!this.entries1.valid) {
            this.entries1.reset();
            Entries entries = this.entries1;
            entries.valid = true;
            this.entries2.valid = false;
            return entries;
        }
        this.entries2.reset();
        Entries entries2 = this.entries2;
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
    public static class Entry {
        public int key;
        public float value;

        public String toString() {
            return this.key + "=" + this.value;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class MapIterator {
        private static final int INDEX_ILLEGAL = -2;
        static final int INDEX_ZERO = -1;
        int currentIndex;
        public boolean hasNext;
        final IntFloatMap map;
        int nextIndex;
        boolean valid = true;

        public MapIterator(IntFloatMap map) {
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
            int[] keyTable = this.map.keyTable;
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
                this.map.hasZeroValue = false;
            } else if (i < 0) {
                throw new IllegalStateException("next must be called before remove.");
            } else {
                int[] keyTable = this.map.keyTable;
                float[] valueTable = this.map.valueTable;
                int mask = this.map.mask;
                int next = (i + 1) & mask;
                while (true) {
                    int key = keyTable[next];
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
                if (i != this.currentIndex) {
                    this.nextIndex--;
                }
            }
            this.currentIndex = INDEX_ILLEGAL;
            IntFloatMap intFloatMap = this.map;
            intFloatMap.size--;
        }
    }

    /* loaded from: classes.dex */
    public static class Entries extends MapIterator implements Iterable<Entry>, Iterator<Entry> {
        private final Entry entry;

        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Entries(IntFloatMap map) {
            super(map);
            this.entry = new Entry();
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.util.Iterator
        public Entry next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            int[] keyTable = this.map.keyTable;
            if (this.nextIndex == -1) {
                Entry entry = this.entry;
                entry.key = 0;
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
        public Iterator<Entry> iterator() {
            return this;
        }

        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator, java.util.Iterator
        public void remove() {
            super.remove();
        }
    }

    /* loaded from: classes.dex */
    public static class Values extends MapIterator {
        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Values(IntFloatMap map) {
            super(map);
        }

        public boolean hasNext() {
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            return this.hasNext;
        }

        public float next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            float value = this.nextIndex == -1 ? this.map.zeroValue : this.map.valueTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return value;
        }

        public Values iterator() {
            return this;
        }

        public FloatArray toArray() {
            FloatArray array = new FloatArray(true, this.map.size);
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }

        public FloatArray toArray(FloatArray array) {
            while (this.hasNext) {
                array.add(next());
            }
            return array;
        }
    }

    /* loaded from: classes.dex */
    public static class Keys extends MapIterator {
        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator, java.util.Iterator
        public /* bridge */ /* synthetic */ void remove() {
            super.remove();
        }

        @Override // com.badlogic.gdx.utils.IntFloatMap.MapIterator
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        public Keys(IntFloatMap map) {
            super(map);
        }

        public int next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            int key = this.nextIndex == -1 ? 0 : this.map.keyTable[this.nextIndex];
            this.currentIndex = this.nextIndex;
            findNextIndex();
            return key;
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
}