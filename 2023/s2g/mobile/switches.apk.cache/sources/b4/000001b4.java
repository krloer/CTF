package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import java.io.IOException;

/* loaded from: classes.dex */
public class ParticleEffectLoader extends AsynchronousAssetLoader<ParticleEffect, ParticleEffectLoadParameter> {
    protected Array<ObjectMap.Entry<String, ResourceData<ParticleEffect>>> items;

    public ParticleEffectLoader(FileHandleResolver resolver) {
        super(resolver);
        this.items = new Array<>();
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, ParticleEffectLoadParameter parameter) {
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v2, types: [com.badlogic.gdx.graphics.g3d.particles.ResourceData, V] */
    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, ParticleEffectLoadParameter parameter) {
        Array<ResourceData.AssetData> assets;
        Json json = new Json();
        ?? r1 = (ResourceData) json.fromJson(ResourceData.class, file);
        synchronized (this.items) {
            ObjectMap.Entry<String, ResourceData<ParticleEffect>> entry = new ObjectMap.Entry<>();
            entry.key = fileName;
            entry.value = r1;
            this.items.add(entry);
            assets = r1.getAssets();
        }
        Array<AssetDescriptor> descriptors = new Array<>();
        Array.ArrayIterator<ResourceData.AssetData> it = assets.iterator();
        while (it.hasNext()) {
            ResourceData.AssetData<?> assetData = it.next();
            if (!resolve(assetData.filename).exists()) {
                assetData.filename = file.parent().child(Gdx.files.internal(assetData.filename).name()).path();
            }
            if (assetData.type == ParticleEffect.class) {
                descriptors.add(new AssetDescriptor(assetData.filename, assetData.type, parameter));
            } else {
                descriptors.add(new AssetDescriptor(assetData.filename, assetData.type));
            }
        }
        return descriptors;
    }

    public void save(ParticleEffect effect, ParticleEffectSaveParameter parameter) throws IOException {
        ResourceData<ParticleEffect> data = new ResourceData<>(effect);
        effect.save(parameter.manager, data);
        if (parameter.batches != null) {
            Array.ArrayIterator<ParticleBatch<?>> it = parameter.batches.iterator();
            while (it.hasNext()) {
                ParticleBatch<?> batch = it.next();
                boolean save = false;
                Array.ArrayIterator<ParticleController> it2 = effect.getControllers().iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    }
                    ParticleController controller = it2.next();
                    if (controller.renderer.isCompatible(batch)) {
                        save = true;
                        break;
                    }
                }
                if (save) {
                    batch.save(parameter.manager, data);
                }
            }
        }
        Json json = new Json();
        json.toJson(data, parameter.file);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public ParticleEffect loadSync(AssetManager manager, String fileName, FileHandle file, ParticleEffectLoadParameter parameter) {
        ResourceData<ParticleEffect> effectData = null;
        synchronized (this.items) {
            int i = 0;
            while (true) {
                if (i >= this.items.size) {
                    break;
                }
                ObjectMap.Entry<String, ResourceData<ParticleEffect>> entry = this.items.get(i);
                if (!entry.key.equals(fileName)) {
                    i++;
                } else {
                    effectData = entry.value;
                    this.items.removeIndex(i);
                    break;
                }
            }
        }
        effectData.resource.load(manager, effectData);
        if (parameter != null) {
            if (parameter.batches != null) {
                Array.ArrayIterator<ParticleBatch<?>> it = parameter.batches.iterator();
                while (it.hasNext()) {
                    ParticleBatch<?> batch = it.next();
                    batch.load(manager, effectData);
                }
            }
            effectData.resource.setBatch(parameter.batches);
        }
        return effectData.resource;
    }

    private <T> T find(Array<?> array, Class<T> type) {
        Array.ArrayIterator<?> it = array.iterator();
        while (it.hasNext()) {
            T t = (T) it.next();
            if (ClassReflection.isAssignableFrom(type, t.getClass())) {
                return t;
            }
        }
        return null;
    }

    /* loaded from: classes.dex */
    public static class ParticleEffectLoadParameter extends AssetLoaderParameters<ParticleEffect> {
        Array<ParticleBatch<?>> batches;

        public ParticleEffectLoadParameter(Array<ParticleBatch<?>> batches) {
            this.batches = batches;
        }
    }

    /* loaded from: classes.dex */
    public static class ParticleEffectSaveParameter extends AssetLoaderParameters<ParticleEffect> {
        Array<ParticleBatch<?>> batches;
        FileHandle file;
        AssetManager manager;

        public ParticleEffectSaveParameter(FileHandle file, AssetManager manager, Array<ParticleBatch<?>> batches) {
            this.batches = batches;
            this.file = file;
            this.manager = manager;
        }
    }
}