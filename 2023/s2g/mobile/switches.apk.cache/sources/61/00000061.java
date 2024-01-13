package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Cubemap;
import com.badlogic.gdx.graphics.CubemapData;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.glutils.KTXTextureData;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class CubemapLoader extends AsynchronousAssetLoader<Cubemap, CubemapParameter> {
    CubemapLoaderInfo info;

    /* loaded from: classes.dex */
    public static class CubemapLoaderInfo {
        Cubemap cubemap;
        CubemapData data;
        String filename;
    }

    /* loaded from: classes.dex */
    public static class CubemapParameter extends AssetLoaderParameters<Cubemap> {
        public Pixmap.Format format = null;
        public Cubemap cubemap = null;
        public CubemapData cubemapData = null;
        public Texture.TextureFilter minFilter = Texture.TextureFilter.Nearest;
        public Texture.TextureFilter magFilter = Texture.TextureFilter.Nearest;
        public Texture.TextureWrap wrapU = Texture.TextureWrap.ClampToEdge;
        public Texture.TextureWrap wrapV = Texture.TextureWrap.ClampToEdge;
    }

    public CubemapLoader(FileHandleResolver resolver) {
        super(resolver);
        this.info = new CubemapLoaderInfo();
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, CubemapParameter parameter) {
        this.info.filename = fileName;
        if (parameter == null || parameter.cubemapData == null) {
            this.info.cubemap = null;
            if (parameter != null) {
                Pixmap.Format format = parameter.format;
                this.info.cubemap = parameter.cubemap;
            }
            if (fileName.contains(".ktx") || fileName.contains(".zktx")) {
                this.info.data = new KTXTextureData(file, false);
            }
        } else {
            this.info.data = parameter.cubemapData;
            this.info.cubemap = parameter.cubemap;
        }
        if (!this.info.data.isPrepared()) {
            this.info.data.prepare();
        }
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public Cubemap loadSync(AssetManager manager, String fileName, FileHandle file, CubemapParameter parameter) {
        CubemapLoaderInfo cubemapLoaderInfo = this.info;
        if (cubemapLoaderInfo == null) {
            return null;
        }
        Cubemap cubemap = cubemapLoaderInfo.cubemap;
        if (cubemap != null) {
            cubemap.load(this.info.data);
        } else {
            cubemap = new Cubemap(this.info.data);
        }
        if (parameter != null) {
            cubemap.setFilter(parameter.minFilter, parameter.magFilter);
            cubemap.setWrap(parameter.wrapU, parameter.wrapV);
        }
        return cubemap;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, CubemapParameter parameter) {
        return null;
    }
}