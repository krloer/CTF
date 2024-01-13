package com.badlogic.gdx.utils;

import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.reflect.ArrayReflection;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public class ArrayMap<K, V> implements Iterable<ObjectMap.Entry<K, V>> {
    private transient Entries entries1;
    private transient Entries entries2;
    public K[] keys;
    private transient Keys keys1;
    private transient Keys keys2;
    public boolean ordered;
    public int size;
    public V[] values;
    private transient Values values1;
    private transient Values values2;

    public ArrayMap() {
        this(true, 16);
    }

    public ArrayMap(int capacity) {
        this(true, capacity);
    }

    public ArrayMap(boolean ordered, int capacity) {
        this.ordered = ordered;
        this.keys = (K[]) new Object[capacity];
        this.values = (V[]) new Object[capacity];
    }

    public ArrayMap(boolean ordered, int capacity, Class keyArrayType, Class valueArrayType) {
        this.ordered = ordered;
        this.keys = (K[]) ((Object[]) ArrayReflection.newInstance(keyArrayType, capacity));
        this.values = (V[]) ((Object[]) ArrayReflection.newInstance(valueArrayType, capacity));
    }

    public ArrayMap(Class keyArrayType, Class valueArrayType) {
        this(false, 16, keyArrayType, valueArrayType);
    }

    public ArrayMap(ArrayMap array) {
        this(array.ordered, array.size, array.keys.getClass().getComponentType(), array.values.getClass().getComponentType());
        this.size = array.size;
        System.arraycopy(array.keys, 0, this.keys, 0, this.size);
        System.arraycopy(array.values, 0, this.values, 0, this.size);
    }

    public int put(K key, V value) {
        int index = indexOfKey(key);
        if (index == -1) {
            int i = this.size;
            if (i == this.keys.length) {
                resize(Math.max(8, (int) (i * 1.75f)));
            }
            int i2 = this.size;
            this.size = i2 + 1;
            index = i2;
        }
        this.keys[index] = key;
        this.values[index] = value;
        return index;
    }

    public int put(K key, V value, int index) {
        int existingIndex = indexOfKey(key);
        if (existingIndex != -1) {
            removeIndex(existingIndex);
        } else {
            int i = this.size;
            if (i == this.keys.length) {
                resize(Math.max(8, (int) (i * 1.75f)));
            }
        }
        K[] kArr = this.keys;
        System.arraycopy(kArr, index, kArr, index + 1, this.size - index);
        V[] vArr = this.values;
        System.arraycopy(vArr, index, vArr, index + 1, this.size - index);
        this.keys[index] = key;
        this.values[index] = value;
        this.size++;
        return index;
    }

    public void putAll(ArrayMap<? extends K, ? extends V> map) {
        putAll(map, 0, map.size);
    }

    public void putAll(ArrayMap<? extends K, ? extends V> map, int offset, int length) {
        if (offset + length > map.size) {
            throw new IllegalArgumentException("offset + length must be <= size: " + offset + " + " + length + " <= " + map.size);
        }
        int sizeNeeded = (this.size + length) - offset;
        if (sizeNeeded >= this.keys.length) {
            resize(Math.max(8, (int) (sizeNeeded * 1.75f)));
        }
        System.arraycopy(map.keys, offset, this.keys, this.size, length);
        System.arraycopy(map.values, offset, this.values, this.size, length);
        this.size += length;
    }

    public V get(K key) {
        return get(key, null);
    }

    public V get(K key, V defaultValue) {
        Object[] keys = this.keys;
        int i = this.size - 1;
        if (key == null) {
            while (i >= 0) {
                if (keys[i] == key) {
                    return this.values[i];
                }
                i--;
            }
        } else {
            while (i >= 0) {
                if (key.equals(keys[i])) {
                    return this.values[i];
                }
                i--;
            }
        }
        return defaultValue;
    }

    public K getKey(V value, boolean identity) {
        Object[] values = this.values;
        int i = this.size - 1;
        if (identity || value == null) {
            while (i >= 0) {
                if (values[i] == value) {
                    return this.keys[i];
                }
                i--;
            }
            return null;
        }
        while (i >= 0) {
            if (value.equals(values[i])) {
                return this.keys[i];
            }
            i--;
        }
        return null;
    }

    public K getKeyAt(int index) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        return this.keys[index];
    }

    public V getValueAt(int index) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        return this.values[index];
    }

    public K firstKey() {
        if (this.size == 0) {
            throw new IllegalStateException("Map is empty.");
        }
        return this.keys[0];
    }

    public V firstValue() {
        if (this.size == 0) {
            throw new IllegalStateException("Map is empty.");
        }
        return this.values[0];
    }

    public void setKey(int index, K key) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        this.keys[index] = key;
    }

    public void setValue(int index, V value) {
        if (index >= this.size) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        this.values[index] = value;
    }

    public void insert(int index, K key, V value) {
        int i = this.size;
        if (index > i) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        if (i == this.keys.length) {
            resize(Math.max(8, (int) (i * 1.75f)));
        }
        if (this.ordered) {
            K[] kArr = this.keys;
            System.arraycopy(kArr, index, kArr, index + 1, this.size - index);
            V[] vArr = this.values;
            System.arraycopy(vArr, index, vArr, index + 1, this.size - index);
        } else {
            K[] kArr2 = this.keys;
            int i2 = this.size;
            kArr2[i2] = kArr2[index];
            V[] vArr2 = this.values;
            vArr2[i2] = vArr2[index];
        }
        this.size++;
        this.keys[index] = key;
        this.values[index] = value;
    }

    public boolean containsKey(K key) {
        K[] keys = this.keys;
        int i = this.size - 1;
        if (key == null) {
            while (i >= 0) {
                int i2 = i - 1;
                if (keys[i] == key) {
                    return true;
                }
                i = i2;
            }
            return false;
        }
        while (i >= 0) {
            int i3 = i - 1;
            if (key.equals(keys[i])) {
                return true;
            }
            i = i3;
        }
        return false;
    }

    public boolean containsValue(V value, boolean identity) {
        V[] values = this.values;
        int i = this.size - 1;
        if (identity || value == null) {
            while (i >= 0) {
                int i2 = i - 1;
                if (values[i] == value) {
                    return true;
                }
                i = i2;
            }
            return false;
        }
        while (i >= 0) {
            int i3 = i - 1;
            if (value.equals(values[i])) {
                return true;
            }
            i = i3;
        }
        return false;
    }

    public int indexOfKey(K key) {
        Object[] keys = this.keys;
        if (key == null) {
            int n = this.size;
            for (int i = 0; i < n; i++) {
                if (keys[i] == key) {
                    return i;
                }
            }
            return -1;
        }
        int n2 = this.size;
        for (int i2 = 0; i2 < n2; i2++) {
            if (key.equals(keys[i2])) {
                return i2;
            }
        }
        return -1;
    }

    public int indexOfValue(V value, boolean identity) {
        Object[] values = this.values;
        if (identity || value == null) {
            int n = this.size;
            for (int i = 0; i < n; i++) {
                if (values[i] == value) {
                    return i;
                }
            }
            return -1;
        }
        int n2 = this.size;
        for (int i2 = 0; i2 < n2; i2++) {
            if (value.equals(values[i2])) {
                return i2;
            }
        }
        return -1;
    }

    public V removeKey(K key) {
        Object[] keys = this.keys;
        if (key == null) {
            int n = this.size;
            for (int i = 0; i < n; i++) {
                if (keys[i] == key) {
                    V value = this.values[i];
                    removeIndex(i);
                    return value;
                }
            }
            return null;
        }
        int n2 = this.size;
        for (int i2 = 0; i2 < n2; i2++) {
            if (key.equals(keys[i2])) {
                V value2 = this.values[i2];
                removeIndex(i2);
                return value2;
            }
        }
        return null;
    }

    public boolean removeValue(V value, boolean identity) {
        Object[] values = this.values;
        if (identity || value == null) {
            int n = this.size;
            for (int i = 0; i < n; i++) {
                if (values[i] == value) {
                    removeIndex(i);
                    return true;
                }
            }
            return false;
        }
        int n2 = this.size;
        for (int i2 = 0; i2 < n2; i2++) {
            if (value.equals(values[i2])) {
                removeIndex(i2);
                return true;
            }
        }
        return false;
    }

    public void removeIndex(int index) {
        int i = this.size;
        if (index >= i) {
            throw new IndexOutOfBoundsException(String.valueOf(index));
        }
        Object[] keys = this.keys;
        this.size = i - 1;
        if (this.ordered) {
            System.arraycopy(keys, index + 1, keys, index, this.size - index);
            V[] vArr = this.values;
            System.arraycopy(vArr, index + 1, vArr, index, this.size - index);
        } else {
            int i2 = this.size;
            keys[index] = keys[i2];
            V[] vArr2 = this.values;
            vArr2[index] = vArr2[i2];
        }
        int i3 = this.size;
        keys[i3] = null;
        this.values[i3] = null;
    }

    public boolean notEmpty() {
        return this.size > 0;
    }

    public boolean isEmpty() {
        return this.size == 0;
    }

    public K peekKey() {
        return this.keys[this.size - 1];
    }

    public V peekValue() {
        return this.values[this.size - 1];
    }

    public void clear(int maximumCapacity) {
        if (this.keys.length <= maximumCapacity) {
            clear();
            return;
        }
        this.size = 0;
        resize(maximumCapacity);
    }

    public void clear() {
        Arrays.fill(this.keys, 0, this.size, (Object) null);
        Arrays.fill(this.values, 0, this.size, (Object) null);
        this.size = 0;
    }

    public void shrink() {
        int length = this.keys.length;
        int i = this.size;
        if (length == i) {
            return;
        }
        resize(i);
    }

    public void ensureCapacity(int additionalCapacity) {
        if (additionalCapacity < 0) {
            throw new IllegalArgumentException("additionalCapacity must be >= 0: " + additionalCapacity);
        }
        int sizeNeeded = this.size + additionalCapacity;
        if (sizeNeeded > this.keys.length) {
            resize(Math.max(Math.max(8, sizeNeeded), (int) (this.size * 1.75f)));
        }
    }

    protected void resize(int newSize) {
        K[] newKeys = (K[]) ((Object[]) ArrayReflection.newInstance(this.keys.getClass().getComponentType(), newSize));
        System.arraycopy(this.keys, 0, newKeys, 0, Math.min(this.size, newKeys.length));
        this.keys = newKeys;
        V[] newValues = (V[]) ((Object[]) ArrayReflection.newInstance(this.values.getClass().getComponentType(), newSize));
        System.arraycopy(this.values, 0, newValues, 0, Math.min(this.size, newValues.length));
        this.values = newValues;
    }

    public void reverse() {
        int i = this.size;
        int lastIndex = i - 1;
        int n = i / 2;
        for (int i2 = 0; i2 < n; i2++) {
            int ii = lastIndex - i2;
            K[] kArr = this.keys;
            K tempKey = kArr[i2];
            kArr[i2] = kArr[ii];
            kArr[ii] = tempKey;
            V[] vArr = this.values;
            V tempValue = vArr[i2];
            vArr[i2] = vArr[ii];
            vArr[ii] = tempValue;
        }
    }

    public void shuffle() {
        for (int i = this.size - 1; i >= 0; i--) {
            int ii = MathUtils.random(i);
            K[] kArr = this.keys;
            K tempKey = kArr[i];
            kArr[i] = kArr[ii];
            kArr[ii] = tempKey;
            V[] vArr = this.values;
            V tempValue = vArr[i];
            vArr[i] = vArr[ii];
            vArr[ii] = tempValue;
        }
    }

    public void truncate(int newSize) {
        if (this.size <= newSize) {
            return;
        }
        for (int i = newSize; i < this.size; i++) {
            this.keys[i] = null;
            this.values[i] = null;
        }
        this.size = newSize;
    }

    public int hashCode() {
        K[] keys = this.keys;
        V[] values = this.values;
        int h = 0;
        int n = this.size;
        for (int i = 0; i < n; i++) {
            K key = keys[i];
            V value = values[i];
            if (key != null) {
                h += key.hashCode() * 31;
            }
            if (value != null) {
                h += value.hashCode();
            }
        }
        return h;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof ArrayMap) {
            ArrayMap other = (ArrayMap) obj;
            if (other.size != this.size) {
                return false;
            }
            K[] keys = this.keys;
            V[] values = this.values;
            int n = this.size;
            for (int i = 0; i < n; i++) {
                K key = keys[i];
                V value = values[i];
                if (value == null) {
                    if (other.get(key, ObjectMap.dummy) != null) {
                        return false;
                    }
                } else if (!value.equals(other.get(key))) {
                    return false;
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
        if (obj instanceof ArrayMap) {
            ArrayMap other = (ArrayMap) obj;
            if (other.size != this.size) {
                return false;
            }
            K[] keys = this.keys;
            V[] values = this.values;
            int n = this.size;
            for (int i = 0; i < n; i++) {
                if (values[i] != other.get(keys[i], ObjectMap.dummy)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public String toString() {
        if (this.size == 0) {
            return "{}";
        }
        K[] keys = this.keys;
        V[] values = this.values;
        StringBuilder buffer = new StringBuilder(32);
        buffer.append('{');
        buffer.append(keys[0]);
        buffer.append('=');
        buffer.append(values[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(", ");
            buffer.append(keys[i]);
            buffer.append('=');
            buffer.append(values[i]);
        }
        buffer.append('}');
        return buffer.toString();
    }

    @Override // java.lang.Iterable
    public Iterator<ObjectMap.Entry<K, V>> iterator() {
        return entries();
    }

    public Entries<K, V> entries() {
        if (Collections.allocateIterators) {
            return new Entries<>(this);
        }
        if (this.entries1 == null) {
            this.entries1 = new Entries(this);
            this.entries2 = new Entries(this);
        }
        if (!this.entries1.valid) {
            Entries<K, V> entries = this.entries1;
            entries.index = 0;
            entries.valid = true;
            this.entries2.valid = false;
            return entries;
        }
        Entries<K, V> entries2 = this.entries2;
        entries2.index = 0;
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
            Values<V> values = this.values1;
            values.index = 0;
            values.valid = true;
            this.values2.valid = false;
            return values;
        }
        Values<V> values2 = this.values2;
        values2.index = 0;
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
            Keys<K> keys = this.keys1;
            keys.index = 0;
            keys.valid = true;
            this.keys2.valid = false;
            return keys;
        }
        Keys<K> keys2 = this.keys2;
        keys2.index = 0;
        keys2.valid = true;
        this.keys1.valid = false;
        return keys2;
    }

    /* loaded from: classes.dex */
    public static class Entries<K, V> implements Iterable<ObjectMap.Entry<K, V>>, Iterator<ObjectMap.Entry<K, V>> {
        int index;
        private final ArrayMap<K, V> map;
        ObjectMap.Entry<K, V> entry = new ObjectMap.Entry<>();
        boolean valid = true;

        public Entries(ArrayMap<K, V> map) {
            this.map = map;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.valid) {
                return this.index < this.map.size;
            }
            throw new GdxRuntimeException("#iterator() cannot be used nested.");
        }

        @Override // java.lang.Iterable
        public Iterator<ObjectMap.Entry<K, V>> iterator() {
            return this;
        }

        @Override // java.util.Iterator
        public ObjectMap.Entry<K, V> next() {
            if (this.index >= this.map.size) {
                throw new NoSuchElementException(String.valueOf(this.index));
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            this.entry.key = this.map.keys[this.index];
            ObjectMap.Entry<K, V> entry = this.entry;
            V[] vArr = this.map.values;
            int i = this.index;
            this.index = i + 1;
            entry.value = vArr[i];
            return this.entry;
        }

        @Override // java.util.Iterator
        public void remove() {
            this.index--;
            this.map.removeIndex(this.index);
        }

        public void reset() {
            this.index = 0;
        }
    }

    /* loaded from: classes.dex */
    public static class Values<V> implements Iterable<V>, Iterator<V> {
        int index;
        private final ArrayMap<Object, V> map;
        boolean valid = true;

        public Values(ArrayMap<Object, V> map) {
            this.map = map;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.valid) {
                return this.index < this.map.size;
            }
            throw new GdxRuntimeException("#iterator() cannot be used nested.");
        }

        @Override // java.lang.Iterable
        public Iterator<V> iterator() {
            return this;
        }

        @Override // java.util.Iterator
        public V next() {
            if (this.index >= this.map.size) {
                throw new NoSuchElementException(String.valueOf(this.index));
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            V[] vArr = this.map.values;
            int i = this.index;
            this.index = i + 1;
            return vArr[i];
        }

        @Override // java.util.Iterator
        public void remove() {
            this.index--;
            this.map.removeIndex(this.index);
        }

        public void reset() {
            this.index = 0;
        }

        public Array<V> toArray() {
            return new Array<>(true, this.map.values, this.index, this.map.size - this.index);
        }

        public Array<V> toArray(Array array) {
            array.addAll(this.map.values, this.index, this.map.size - this.index);
            return array;
        }
    }

    /* loaded from: classes.dex */
    public static class Keys<K> implements Iterable<K>, Iterator<K> {
        int index;
        private final ArrayMap<K, Object> map;
        boolean valid = true;

        public Keys(ArrayMap<K, Object> map) {
            this.map = map;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.valid) {
                return this.index < this.map.size;
            }
            throw new GdxRuntimeException("#iterator() cannot be used nested.");
        }

        @Override // java.lang.Iterable
        public Iterator<K> iterator() {
            return this;
        }

        @Override // java.util.Iterator
        public K next() {
            if (this.index >= this.map.size) {
                throw new NoSuchElementException(String.valueOf(this.index));
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K[] kArr = this.map.keys;
            int i = this.index;
            this.index = i + 1;
            return kArr[i];
        }

        @Override // java.util.Iterator
        public void remove() {
            this.index--;
            this.map.removeIndex(this.index);
        }

        public void reset() {
            this.index = 0;
        }

        public Array<K> toArray() {
            return new Array<>(true, this.map.keys, this.index, this.map.size - this.index);
        }

        public Array<K> toArray(Array array) {
            array.addAll(this.map.keys, this.index, this.map.size - this.index);
            return array;
        }
    }
}