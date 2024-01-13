package com.badlogic.gdx.utils;

/* loaded from: classes.dex */
public class IdentityMap<K, V> extends ObjectMap<K, V> {
    public IdentityMap() {
    }

    public IdentityMap(int initialCapacity) {
        super(initialCapacity);
    }

    public IdentityMap(int initialCapacity, float loadFactor) {
        super(initialCapacity, loadFactor);
    }

    public IdentityMap(IdentityMap<K, V> map) {
        super(map);
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    protected int place(K item) {
        return (int) ((System.identityHashCode(item) * (-7046029254386353131L)) >>> this.shift);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.badlogic.gdx.utils.ObjectMap
    public int locateKey(K key) {
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
            if (other == key) {
                return i;
            }
            i = (i + 1) & this.mask;
        }
    }

    @Override // com.badlogic.gdx.utils.ObjectMap
    public int hashCode() {
        int h = this.size;
        K[] keyTable = this.keyTable;
        V[] valueTable = this.valueTable;
        int n = keyTable.length;
        for (int i = 0; i < n; i++) {
            K key = keyTable[i];
            if (key != null) {
                h += System.identityHashCode(key);
                V value = valueTable[i];
                if (value != null) {
                    h += value.hashCode();
                }
            }
        }
        return h;
    }
}