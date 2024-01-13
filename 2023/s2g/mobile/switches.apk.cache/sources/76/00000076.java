package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class TextureAtlasLoader extends SynchronousAssetLoader<TextureAtlas, TextureAtlasParameter> {
    TextureAtlas.TextureAtlasData data;

    public TextureAtlasLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.SynchronousAssetLoader
    public TextureAtlas load(AssetManager assetManager, String fileName, FileHandle file, TextureAtlasParameter parameter) {
        Array.ArrayIterator<TextureAtlas.TextureAtlasData.Page> it = this.data.getPages().iterator();
        while (it.hasNext()) {
            TextureAtlas.TextureAtlasData.Page page = it.next();
            Texture texture = (Texture) assetManager.get(page.textureFile.path().replaceAll("\\\\", "/"), Texture.class);
            page.texture = texture;
        }
        TextureAtlas atlas = new TextureAtlas(this.data);
        this.data = null;
        return atlas;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle atlasFile, TextureAtlasParameter parameter) {
        FileHandle imgDir = atlasFile.parent();
        if (parameter != null) {
            this.data = new TextureAtlas.TextureAtlasData(atlasFile, imgDir, parameter.flip);
        } else {
            this.data = new TextureAtlas.TextureAtlasData(atlasFile, imgDir, false);
        }
        Array<AssetDescriptor> dependencies = new Array<>();
        Array.ArrayIterator<TextureAtlas.TextureAtlasData.Page> it = this.data.getPages().iterator();
        while (it.hasNext()) {
            TextureAtlas.TextureAtlasData.Page page = it.next();
            TextureLoader.TextureParameter params = new TextureLoader.TextureParameter();
            params.format = page.format;
            params.genMipMaps = page.useMipMaps;
            params.minFilter = page.minFilter;
            params.magFilter = page.magFilter;
            dependencies.add(new AssetDescriptor(page.textureFile, Texture.class, params));
        }
        return dependencies;
    }

    /* loaded from: classes.dex */
    public static class TextureAtlasParameter extends AssetLoaderParameters<TextureAtlas> {
        public boolean flip;

        public TextureAtlasParameter() {
            this.flip = false;
        }

        public TextureAtlasParameter(boolean flip) {
            this.flip = false;
            this.flip = flip;
        }
    }
}