package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import com.badlogic.gdx.utils.reflect.ReflectionException;

/* loaded from: classes.dex */
public class ResourceData<T> implements Json.Serializable {
    private int currentLoadIndex;
    private Array<SaveData> data;
    public T resource;
    Array<AssetData> sharedAssets;
    private ObjectMap<String, SaveData> uniqueData;

    /* loaded from: classes.dex */
    public interface Configurable<T> {
        void load(AssetManager assetManager, ResourceData<T> resourceData);

        void save(AssetManager assetManager, ResourceData<T> resourceData);
    }

    /* loaded from: classes.dex */
    public static class SaveData implements Json.Serializable {
        protected ResourceData resources;
        ObjectMap<String, Object> data = new ObjectMap<>();
        IntArray assets = new IntArray();
        private int loadIndex = 0;

        public SaveData() {
        }

        public SaveData(ResourceData resources) {
            this.resources = resources;
        }

        public <K> void saveAsset(String filename, Class<K> type) {
            int i = this.resources.getAssetData(filename, type);
            if (i == -1) {
                this.resources.sharedAssets.add(new AssetData(filename, type));
                i = this.resources.sharedAssets.size - 1;
            }
            this.assets.add(i);
        }

        public void save(String key, Object value) {
            this.data.put(key, value);
        }

        public AssetDescriptor loadAsset() {
            if (this.loadIndex == this.assets.size) {
                return null;
            }
            Array<AssetData> array = this.resources.sharedAssets;
            IntArray intArray = this.assets;
            int i = this.loadIndex;
            this.loadIndex = i + 1;
            AssetData data = array.get(intArray.get(i));
            return new AssetDescriptor(data.filename, data.type);
        }

        public <K> K load(String key) {
            return (K) this.data.get(key);
        }

        @Override // com.badlogic.gdx.utils.Json.Serializable
        public void write(Json json) {
            json.writeValue("data", this.data, ObjectMap.class);
            json.writeValue("indices", this.assets.toArray(), int[].class);
        }

        @Override // com.badlogic.gdx.utils.Json.Serializable
        public void read(Json json, JsonValue jsonData) {
            this.data = (ObjectMap) json.readValue("data", ObjectMap.class, jsonData);
            this.assets.addAll((int[]) json.readValue("indices", int[].class, jsonData));
        }
    }

    /* loaded from: classes.dex */
    public static class AssetData<T> implements Json.Serializable {
        public String filename;
        public Class<T> type;

        public AssetData() {
        }

        public AssetData(String filename, Class<T> type) {
            this.filename = filename;
            this.type = type;
        }

        @Override // com.badlogic.gdx.utils.Json.Serializable
        public void write(Json json) {
            json.writeValue("filename", this.filename);
            json.writeValue("type", this.type.getName());
        }

        @Override // com.badlogic.gdx.utils.Json.Serializable
        public void read(Json json, JsonValue jsonData) {
            this.filename = (String) json.readValue("filename", String.class, jsonData);
            String className = (String) json.readValue("type", String.class, jsonData);
            try {
                this.type = ClassReflection.forName(className);
            } catch (ReflectionException e) {
                throw new GdxRuntimeException("Class not found: " + className, e);
            }
        }
    }

    public ResourceData() {
        this.uniqueData = new ObjectMap<>();
        this.data = new Array<>(true, 3, SaveData.class);
        this.sharedAssets = new Array<>();
        this.currentLoadIndex = 0;
    }

    public ResourceData(T resource) {
        this();
        this.resource = resource;
    }

    <K> int getAssetData(String filename, Class<K> type) {
        int i = 0;
        Array.ArrayIterator<AssetData> it = this.sharedAssets.iterator();
        while (it.hasNext()) {
            AssetData data = it.next();
            if (data.filename.equals(filename) && data.type.equals(type)) {
                return i;
            }
            i++;
        }
        return -1;
    }

    public Array<AssetDescriptor> getAssetDescriptors() {
        Array<AssetDescriptor> descriptors = new Array<>();
        Array.ArrayIterator<AssetData> it = this.sharedAssets.iterator();
        while (it.hasNext()) {
            AssetData data = it.next();
            descriptors.add(new AssetDescriptor(data.filename, data.type));
        }
        return descriptors;
    }

    public Array<AssetData> getAssets() {
        return this.sharedAssets;
    }

    public SaveData createSaveData() {
        SaveData saveData = new SaveData(this);
        this.data.add(saveData);
        return saveData;
    }

    public SaveData createSaveData(String key) {
        SaveData saveData = new SaveData(this);
        if (this.uniqueData.containsKey(key)) {
            throw new RuntimeException("Key already used, data must be unique, use a different key");
        }
        this.uniqueData.put(key, saveData);
        return saveData;
    }

    public SaveData getSaveData() {
        Array<SaveData> array = this.data;
        int i = this.currentLoadIndex;
        this.currentLoadIndex = i + 1;
        return array.get(i);
    }

    public SaveData getSaveData(String key) {
        return this.uniqueData.get(key);
    }

    @Override // com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        json.writeValue("unique", this.uniqueData, ObjectMap.class);
        json.writeValue("data", this.data, Array.class, SaveData.class);
        json.writeValue("assets", this.sharedAssets.toArray(AssetData.class), AssetData[].class);
        json.writeValue("resource", this.resource, (Class) null);
    }

    @Override // com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        this.uniqueData = (ObjectMap) json.readValue("unique", ObjectMap.class, jsonData);
        ObjectMap.Entries<String, SaveData> it = this.uniqueData.entries().iterator();
        while (it.hasNext()) {
            ObjectMap.Entry entry = it.next();
            ((SaveData) entry.value).resources = this;
        }
        this.data = (Array) json.readValue("data", (Class<Object>) Array.class, SaveData.class, jsonData);
        Array.ArrayIterator<SaveData> it2 = this.data.iterator();
        while (it2.hasNext()) {
            SaveData saveData = it2.next();
            saveData.resources = this;
        }
        this.sharedAssets.addAll((Array) json.readValue("assets", (Class<Object>) Array.class, AssetData.class, jsonData));
        this.resource = (T) json.readValue("resource", (Class<Object>) null, jsonData);
    }
}