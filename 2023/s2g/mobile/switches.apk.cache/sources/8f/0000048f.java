package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.ObjectMap;
import java.util.NoSuchElementException;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class OrderedMap<K, V> extends ObjectMap<K, V> {
    final Array<K> keys;

    public OrderedMap() {
        this.keys = new Array<>();
    }

    public OrderedMap(int initialCapacity) {
        super(initialCapacity);
        this.keys = new Array<>(initialCapacity);
    }

    public OrderedMap(int initialCapacity, float loadFactor) {
        super(initialCapacity, loadFactor);
        this.keys = new Array<>(initialCapacity);
    }

    public OrderedMap(OrderedMap<? extends K, ? extends V> map) {
        super(map);
        this.keys = new Array<>(map.keys);
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public V put(K key, V value) {
        int i = locateKey(key);
        if (i >= 0) {
            V oldValue = this.valueTable[i];
            this.valueTable[i] = value;
            return oldValue;
        }
        int i2 = -(i + 1);
        this.keyTable[i2] = key;
        this.valueTable[i2] = value;
        this.keys.add(key);
        int i3 = this.size + 1;
        this.size = i3;
        if (i3 >= this.threshold) {
            resize(this.keyTable.length << 1);
            return null;
        }
        return null;
    }

    public <T extends K> void putAll(OrderedMap<T, ? extends V> map) {
        ensureCapacity(map.size);
        T[] tArr = map.keys.items;
        int n = map.keys.size;
        for (int i = 0; i < n; i++) {
            T t = tArr[i];
            put(t, map.get(t));
        }
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public V remove(K key) {
        this.keys.removeValue(key, false);
        return (V) super.remove(key);
    }

    public V removeIndex(int index) {
        return (V) super.remove(this.keys.removeIndex(index));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean alter(K before, K after) {
        int index;
        if (containsKey(after) || (index = this.keys.indexOf(before, false)) == -1) {
            return false;
        }
        super.put(after, super.remove(before));
        this.keys.set(index, after);
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean alterIndex(int index, K after) {
        if (index < 0 || index >= this.size || containsKey(after)) {
            return false;
        }
        super.put(after, super.remove(this.keys.get(index)));
        this.keys.set(index, after);
        return true;
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public void clear(int maximumCapacity) {
        this.keys.clear();
        super.clear(maximumCapacity);
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public void clear() {
        this.keys.clear();
        super.clear();
    }

    public Array<K> orderedKeys() {
        return this.keys;
    }

    @Override // com.badlogic.gdx.utils.ObjectMap, java.lang.Iterable
    public ObjectMap.Entries<K, V> iterator() {
        return entries();
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public ObjectMap.Entries<K, V> entries() {
        if (Collections.allocateIterators) {
            return new OrderedMapEntries(this);
        }
        if (this.entries1 == null) {
            this.entries1 = new OrderedMapEntries(this);
            this.entries2 = new OrderedMapEntries(this);
        }
        if (!this.entries1.valid) {
            this.entries1.reset();
            this.entries1.valid = true;
            this.entries2.valid = false;
            return this.entries1;
        }
        this.entries2.reset();
        this.entries2.valid = true;
        this.entries1.valid = false;
        return this.entries2;
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public ObjectMap.Values<V> values() {
        if (Collections.allocateIterators) {
            return new OrderedMapValues(this);
        }
        if (this.values1 == null) {
            this.values1 = new OrderedMapValues(this);
            this.values2 = new OrderedMapValues(this);
        }
        if (!this.values1.valid) {
            this.values1.reset();
            this.values1.valid = true;
            this.values2.valid = false;
            return this.values1;
        }
        this.values2.reset();
        this.values2.valid = true;
        this.values1.valid = false;
        return this.values2;
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public ObjectMap.Keys<K> keys() {
        if (Collections.allocateIterators) {
            return new OrderedMapKeys(this);
        }
        if (this.keys1 == null) {
            this.keys1 = new OrderedMapKeys(this);
            this.keys2 = new OrderedMapKeys(this);
        }
        if (!this.keys1.valid) {
            this.keys1.reset();
            this.keys1.valid = true;
            this.keys2.valid = false;
            return this.keys1;
        }
        this.keys2.reset();
        this.keys2.valid = true;
        this.keys1.valid = false;
        return this.keys2;
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    protected String toString(String separator, boolean braces) {
        if (this.size == 0) {
            return braces ? "{}" : BuildConfig.FLAVOR;
        }
        java.lang.StringBuilder buffer = new java.lang.StringBuilder(32);
        if (braces) {
            buffer.append('{');
        }
        Array<K> keys = this.keys;
        int n = keys.size;
        for (int i = 0; i < n; i++) {
            K key = keys.get(i);
            if (i > 0) {
                buffer.append(separator);
            }
            Object obj = "(this)";
            buffer.append(key == this ? "(this)" : key);
            buffer.append('=');
            V value = get(key);
            if (value != this) {
                obj = value;
            }
            buffer.append(obj);
        }
        if (braces) {
            buffer.append('}');
        }
        return buffer.toString();
    }

    /* loaded from: classes.dex */
    public static class OrderedMapEntries<K, V> extends ObjectMap.Entries<K, V> {
        private Array<K> keys;

        public OrderedMapEntries(OrderedMap<K, V> map) {
            super(map);
            this.keys = map.keys;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Entries, com.badlogic.gdx.utils.ObjectMap.MapIterator
        public void reset() {
            this.currentIndex = -1;
            this.nextIndex = 0;
            this.hasNext = this.map.size > 0;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Entries, java.util.Iterator
        public ObjectMap.Entry next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            this.currentIndex = this.nextIndex;
            this.entry.key = this.keys.get(this.nextIndex);
            this.entry.value = this.map.get(this.entry.key);
            this.nextIndex++;
            this.hasNext = this.nextIndex < this.map.size;
            return this.entry;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Entries, com.badlogic.gdx.utils.ObjectMap.MapIterator, java.util.Iterator
        public void remove() {
            if (this.currentIndex < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            this.map.remove(this.entry.key);
            this.nextIndex--;
            this.currentIndex = -1;
        }
    }

    /* loaded from: classes.dex */
    public static class OrderedMapKeys<K> extends ObjectMap.Keys<K> {
        private Array<K> keys;

        public OrderedMapKeys(OrderedMap<K, ?> map) {
            super(map);
            this.keys = map.keys;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Keys, com.badlogic.gdx.utils.ObjectMap.MapIterator
        public void reset() {
            this.currentIndex = -1;
            this.nextIndex = 0;
            this.hasNext = this.map.size > 0;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Keys, java.util.Iterator
        public K next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K key = this.keys.get(this.nextIndex);
            this.currentIndex = this.nextIndex;
            this.nextIndex++;
            this.hasNext = this.nextIndex < this.map.size;
            return key;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Keys, com.badlogic.gdx.utils.ObjectMap.MapIterator, java.util.Iterator
        public void remove() {
            if (this.currentIndex < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            ((OrderedMap) this.map).removeIndex(this.currentIndex);
            this.nextIndex = this.currentIndex;
            this.currentIndex = -1;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Keys
        public Array<K> toArray(Array<K> array) {
            array.addAll((Array<? extends K>) this.keys, this.nextIndex, this.keys.size - this.nextIndex);
            this.nextIndex = this.keys.size;
            this.hasNext = false;
            return array;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Keys
        public Array<K> toArray() {
            return toArray(new Array<>(true, this.keys.size - this.nextIndex));
        }
    }

    /* loaded from: classes.dex */
    public static class OrderedMapValues<V> extends ObjectMap.Values<V> {
        private Array keys;

        public OrderedMapValues(OrderedMap<?, V> map) {
            super(map);
            this.keys = map.keys;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Values, com.badlogic.gdx.utils.ObjectMap.MapIterator
        public void reset() {
            this.currentIndex = -1;
            this.nextIndex = 0;
            this.hasNext = this.map.size > 0;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Values, java.util.Iterator
        public V next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            V value = this.map.get(this.keys.get(this.nextIndex));
            this.currentIndex = this.nextIndex;
            this.nextIndex++;
            this.hasNext = this.nextIndex < this.map.size;
            return value;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Values, com.badlogic.gdx.utils.ObjectMap.MapIterator, java.util.Iterator
        public void remove() {
            if (this.currentIndex < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            ((OrderedMap) this.map).removeIndex(this.currentIndex);
            this.nextIndex = this.currentIndex;
            this.currentIndex = -1;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Values
        public Array<V> toArray(Array<V> array) {
            int n = this.keys.size;
            array.ensureCapacity(n - this.nextIndex);
            Object[] keys = this.keys.items;
            for (int i = this.nextIndex; i < n; i++) {
                array.add(this.map.get(keys[i]));
            }
            int i2 = n - 1;
            this.currentIndex = i2;
            this.nextIndex = n;
            this.hasNext = false;
            return array;
        }

        @Override // com.badlogic.gdx.utils.ObjectMap.Values
        public Array<V> toArray() {
            return toArray(new Array<>(true, this.keys.size - this.nextIndex));
        }
    }
}