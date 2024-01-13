package com.badlogic.gdx.maps;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import java.util.Iterator;

/* loaded from: classes.dex */
public class MapLayers implements Iterable<MapLayer> {
    private Array<MapLayer> layers = new Array<>();

    public MapLayer get(int index) {
        return this.layers.get(index);
    }

    public MapLayer get(String name) {
        int n = this.layers.size;
        for (int i = 0; i < n; i++) {
            MapLayer layer = this.layers.get(i);
            if (name.equals(layer.getName())) {
                return layer;
            }
        }
        return null;
    }

    public int getIndex(String name) {
        return getIndex(get(name));
    }

    public int getIndex(MapLayer layer) {
        return this.layers.indexOf(layer, true);
    }

    public int getCount() {
        return this.layers.size;
    }

    public void add(MapLayer layer) {
        this.layers.add(layer);
    }

    public void remove(int index) {
        this.layers.removeIndex(index);
    }

    public void remove(MapLayer layer) {
        this.layers.removeValue(layer, true);
    }

    public int size() {
        return this.layers.size;
    }

    public <T extends MapLayer> Array<T> getByType(Class<T> type) {
        return getByType(type, new Array<>());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public <T extends MapLayer> Array<T> getByType(Class<T> type, Array<T> fill) {
        fill.clear();
        int n = this.layers.size;
        for (int i = 0; i < n; i++) {
            MapLayer layer = this.layers.get(i);
            if (ClassReflection.isInstance(type, layer)) {
                fill.add(layer);
            }
        }
        return fill;
    }

    @Override // java.lang.Iterable
    public Iterator<MapLayer> iterator() {
        return this.layers.iterator();
    }
}