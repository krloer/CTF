package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.Texture;

/* loaded from: classes.dex */
public interface TextureProvider {
    Texture load(String str);

    /* loaded from: classes.dex */
    public static class FileTextureProvider implements TextureProvider {
        private Texture.TextureFilter magFilter;
        private Texture.TextureFilter minFilter;
        private Texture.TextureWrap uWrap;
        private boolean useMipMaps;
        private Texture.TextureWrap vWrap;

        public FileTextureProvider() {
            Texture.TextureFilter textureFilter = Texture.TextureFilter.Linear;
            this.magFilter = textureFilter;
            this.minFilter = textureFilter;
            Texture.TextureWrap textureWrap = Texture.TextureWrap.Repeat;
            this.vWrap = textureWrap;
            this.uWrap = textureWrap;
            this.useMipMaps = false;
        }

        public FileTextureProvider(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, Texture.TextureWrap uWrap, Texture.TextureWrap vWrap, boolean useMipMaps) {
            this.minFilter = minFilter;
            this.magFilter = magFilter;
            this.uWrap = uWrap;
            this.vWrap = vWrap;
            this.useMipMaps = useMipMaps;
        }

        @Override // com.badlogic.gdx.graphics.g3d.utils.TextureProvider
        public Texture load(String fileName) {
            Texture result = new Texture(Gdx.files.internal(fileName), this.useMipMaps);
            result.setFilter(this.minFilter, this.magFilter);
            result.setWrap(this.uWrap, this.vWrap);
            return result;
        }
    }

    /* loaded from: classes.dex */
    public static class AssetTextureProvider implements TextureProvider {
        public final AssetManager assetManager;

        public AssetTextureProvider(AssetManager assetManager) {
            this.assetManager = assetManager;
        }

        @Override // com.badlogic.gdx.graphics.g3d.utils.TextureProvider
        public Texture load(String fileName) {
            return (Texture) this.assetManager.get(fileName, Texture.class);
        }
    }
}