package com.badlogic.gdx.maps;

import com.badlogic.gdx.utils.ObjectMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public class MapProperties {
    private ObjectMap<String, Object> properties = new ObjectMap<>();

    public boolean containsKey(String key) {
        return this.properties.containsKey(key);
    }

    public Object get(String key) {
        return this.properties.get(key);
    }

    public <T> T get(String key, Class<T> clazz) {
        return (T) get(key);
    }

    public <T> T get(String key, T defaultValue, Class<T> clazz) {
        T t = (T) get(key);
        return t == null ? defaultValue : t;
    }

    public void put(String key, Object value) {
        this.properties.put(key, value);
    }

    public void putAll(MapProperties properties) {
        this.properties.putAll(properties.properties);
    }

    public void remove(String key) {
        this.properties.remove(key);
    }

    public void clear() {
        this.properties.clear();
    }

    public Iterator<String> getKeys() {
        return this.properties.keys();
    }

    public Iterator<Object> getValues() {
        return this.properties.values();
    }
}