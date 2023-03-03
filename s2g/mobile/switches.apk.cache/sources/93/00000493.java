package com.badlogic.gdx.utils;

import com.badlogic.gdx.utils.ObjectSet;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public class OrderedSet<T> extends ObjectSet<T> {
    final Array<T> items;
    transient OrderedSetIterator iterator1;
    transient OrderedSetIterator iterator2;

    public OrderedSet() {
        this.items = new Array<>();
    }

    public OrderedSet(int initialCapacity, float loadFactor) {
        super(initialCapacity, loadFactor);
        this.items = new Array<>(initialCapacity);
    }

    public OrderedSet(int initialCapacity) {
        super(initialCapacity);
        this.items = new Array<>(initialCapacity);
    }

    public OrderedSet(OrderedSet<? extends T> set) {
        super(set);
        this.items = new Array<>(set.items);
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public boolean add(T key) {
        if (super.add(key)) {
            this.items.add(key);
            return true;
        }
        return false;
    }

    public boolean add(T key, int index) {
        if (!super.add(key)) {
            int oldIndex = this.items.indexOf(key, true);
            if (oldIndex != index) {
                Array<T> array = this.items;
                array.insert(index, array.removeIndex(oldIndex));
                return false;
            }
            return false;
        }
        this.items.insert(index, key);
        return true;
    }

    public void addAll(OrderedSet<T> set) {
        ensureCapacity(set.size);
        T[] keys = set.items.items;
        int n = set.items.size;
        for (int i = 0; i < n; i++) {
            add(keys[i]);
        }
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public boolean remove(T key) {
        if (super.remove(key)) {
            this.items.removeValue(key, false);
            return true;
        }
        return false;
    }

    public T removeIndex(int index) {
        T key = this.items.removeIndex(index);
        super.remove(key);
        return key;
    }

    public boolean alter(T before, T after) {
        if (!contains(after) && super.remove(before)) {
            super.add(after);
            Array<T> array = this.items;
            array.set(array.indexOf(before, false), after);
            return true;
        }
        return false;
    }

    public boolean alterIndex(int index, T after) {
        if (index < 0 || index >= this.size || contains(after)) {
            return false;
        }
        super.remove(this.items.get(index));
        super.add(after);
        this.items.set(index, after);
        return true;
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public void clear(int maximumCapacity) {
        this.items.clear();
        super.clear(maximumCapacity);
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public void clear() {
        this.items.clear();
        super.clear();
    }

    public Array<T> orderedItems() {
        return this.items;
    }

    @Override // com.badlogic.gdx.utils.ObjectSet, java.lang.Iterable
    public OrderedSetIterator<T> iterator() {
        if (Collections.allocateIterators) {
            return new OrderedSetIterator<>(this);
        }
        if (this.iterator1 == null) {
            this.iterator1 = new OrderedSetIterator(this);
            this.iterator2 = new OrderedSetIterator(this);
        }
        if (!this.iterator1.valid) {
            this.iterator1.reset();
            OrderedSetIterator<T> orderedSetIterator = this.iterator1;
            orderedSetIterator.valid = true;
            this.iterator2.valid = false;
            return orderedSetIterator;
        }
        this.iterator2.reset();
        OrderedSetIterator<T> orderedSetIterator2 = this.iterator2;
        orderedSetIterator2.valid = true;
        this.iterator1.valid = false;
        return orderedSetIterator2;
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public String toString() {
        if (this.size == 0) {
            return "{}";
        }
        T[] items = this.items.items;
        java.lang.StringBuilder buffer = new java.lang.StringBuilder(32);
        buffer.append('{');
        buffer.append(items[0]);
        for (int i = 1; i < this.size; i++) {
            buffer.append(", ");
            buffer.append(items[i]);
        }
        buffer.append('}');
        return buffer.toString();
    }

    @Override // com.badlogic.gdx.utils.ObjectSet
    public String toString(String separator) {
        return this.items.toString(separator);
    }

    /* loaded from: classes.dex */
    public static class OrderedSetIterator<K> extends ObjectSet.ObjectSetIterator<K> {
        private Array<K> items;

        public OrderedSetIterator(OrderedSet<K> set) {
            super(set);
            this.items = set.items;
        }

        @Override // com.badlogic.gdx.utils.ObjectSet.ObjectSetIterator
        public void reset() {
            this.nextIndex = 0;
            this.hasNext = this.set.size > 0;
        }

        @Override // com.badlogic.gdx.utils.ObjectSet.ObjectSetIterator, java.util.Iterator
        public K next() {
            if (!this.hasNext) {
                throw new NoSuchElementException();
            }
            if (!this.valid) {
                throw new GdxRuntimeException("#iterator() cannot be used nested.");
            }
            K key = this.items.get(this.nextIndex);
            this.nextIndex++;
            this.hasNext = this.nextIndex < this.set.size;
            return key;
        }

        @Override // com.badlogic.gdx.utils.ObjectSet.ObjectSetIterator, java.util.Iterator
        public void remove() {
            if (this.nextIndex < 0) {
                throw new IllegalStateException("next must be called before remove.");
            }
            this.nextIndex--;
            ((OrderedSet) this.set).removeIndex(this.nextIndex);
        }

        @Override // com.badlogic.gdx.utils.ObjectSet.ObjectSetIterator
        public Array<K> toArray(Array<K> array) {
            array.addAll((Array<? extends K>) this.items, this.nextIndex, this.items.size - this.nextIndex);
            this.nextIndex = this.items.size;
            this.hasNext = false;
            return array;
        }

        @Override // com.badlogic.gdx.utils.ObjectSet.ObjectSetIterator
        public Array<K> toArray() {
            return toArray(new Array<>(true, this.set.size - this.nextIndex));
        }
    }

    public static <T> OrderedSet<T> with(T... array) {
        OrderedSet<T> set = new OrderedSet<>();
        set.addAll(array);
        return set;
    }
}