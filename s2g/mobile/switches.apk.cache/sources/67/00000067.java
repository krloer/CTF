package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.ModelLoader.ModelParameters;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g3d.Model;
import com.badlogic.gdx.graphics.g3d.model.data.ModelData;
import com.badlogic.gdx.graphics.g3d.model.data.ModelMaterial;
import com.badlogic.gdx.graphics.g3d.model.data.ModelTexture;
import com.badlogic.gdx.graphics.g3d.utils.TextureProvider;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.ObjectMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class ModelLoader<P extends ModelParameters> extends AsynchronousAssetLoader<Model, P> {
    protected ModelParameters defaultParameters;
    protected Array<ObjectMap.Entry<String, ModelData>> items;

    public abstract ModelData loadModelData(FileHandle fileHandle, P p);

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public /* bridge */ /* synthetic */ Array getDependencies(String str, FileHandle fileHandle, AssetLoaderParameters assetLoaderParameters) {
        return getDependencies(str, fileHandle, (FileHandle) ((ModelParameters) assetLoaderParameters));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public /* bridge */ /* synthetic */ void loadAsync(AssetManager assetManager, String str, FileHandle fileHandle, AssetLoaderParameters assetLoaderParameters) {
        loadAsync(assetManager, str, fileHandle, (FileHandle) ((ModelParameters) assetLoaderParameters));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public /* bridge */ /* synthetic */ Model loadSync(AssetManager assetManager, String str, FileHandle fileHandle, AssetLoaderParameters assetLoaderParameters) {
        return loadSync(assetManager, str, fileHandle, (FileHandle) ((ModelParameters) assetLoaderParameters));
    }

    public ModelLoader(FileHandleResolver resolver) {
        super(resolver);
        this.items = new Array<>();
        this.defaultParameters = new ModelParameters();
    }

    public ModelData loadModelData(FileHandle fileHandle) {
        return loadModelData(fileHandle, null);
    }

    public Model loadModel(FileHandle fileHandle, TextureProvider textureProvider, P parameters) {
        ModelData data = loadModelData(fileHandle, parameters);
        if (data == null) {
            return null;
        }
        return new Model(data, textureProvider);
    }

    public Model loadModel(FileHandle fileHandle, P parameters) {
        return loadModel(fileHandle, new TextureProvider.FileTextureProvider(), parameters);
    }

    public Model loadModel(FileHandle fileHandle, TextureProvider textureProvider) {
        return loadModel(fileHandle, textureProvider, null);
    }

    public Model loadModel(FileHandle fileHandle) {
        return loadModel(fileHandle, new TextureProvider.FileTextureProvider(), null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [V, com.badlogic.gdx.graphics.g3d.model.data.ModelData] */
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, P parameters) {
        Array<AssetDescriptor> deps = new Array<>();
        ?? loadModelData = loadModelData(file, parameters);
        if (loadModelData == 0) {
            return deps;
        }
        ObjectMap.Entry<String, ModelData> item = new ObjectMap.Entry<>();
        item.key = fileName;
        item.value = loadModelData;
        synchronized (this.items) {
            this.items.add(item);
        }
        TextureLoader.TextureParameter textureParameter = parameters != null ? parameters.textureParameter : this.defaultParameters.textureParameter;
        Array.ArrayIterator<ModelMaterial> it = loadModelData.materials.iterator();
        while (it.hasNext()) {
            ModelMaterial modelMaterial = it.next();
            if (modelMaterial.textures != null) {
                Array.ArrayIterator<ModelTexture> it2 = modelMaterial.textures.iterator();
                while (it2.hasNext()) {
                    ModelTexture modelTexture = it2.next();
                    deps.add(new AssetDescriptor(modelTexture.fileName, Texture.class, textureParameter));
                }
            }
        }
        return deps;
    }

    public void loadAsync(AssetManager manager, String fileName, FileHandle file, P parameters) {
    }

    public Model loadSync(AssetManager manager, String fileName, FileHandle file, P parameters) {
        ModelData data = null;
        synchronized (this.items) {
            for (int i = 0; i < this.items.size; i++) {
                if (this.items.get(i).key.equals(fileName)) {
                    data = this.items.get(i).value;
                    this.items.removeIndex(i);
                }
            }
        }
        if (data == null) {
            return null;
        }
        Model result = new Model(data, new TextureProvider.AssetTextureProvider(manager));
        Iterator<Disposable> disposables = result.getManagedDisposables().iterator();
        while (disposables.hasNext()) {
            Disposable disposable = disposables.next();
            if (disposable instanceof Texture) {
                disposables.remove();
            }
        }
        return result;
    }

    /* loaded from: classes.dex */
    public static class ModelParameters extends AssetLoaderParameters<Model> {
        public TextureLoader.TextureParameter textureParameter = new TextureLoader.TextureParameter();

        public ModelParameters() {
            TextureLoader.TextureParameter textureParameter = this.textureParameter;
            Texture.TextureFilter textureFilter = Texture.TextureFilter.Linear;
            textureParameter.magFilter = textureFilter;
            textureParameter.minFilter = textureFilter;
            TextureLoader.TextureParameter textureParameter2 = this.textureParameter;
            Texture.TextureWrap textureWrap = Texture.TextureWrap.Repeat;
            textureParameter2.wrapV = textureWrap;
            textureParameter2.wrapU = textureWrap;
        }
    }
}