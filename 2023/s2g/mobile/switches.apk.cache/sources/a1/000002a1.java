package com.badlogic.gdx.maps;

import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.utils.ObjectMap;

/* loaded from: classes.dex */
public interface ImageResolver {
    TextureRegion getImage(String str);

    /* loaded from: classes.dex */
    public static class DirectImageResolver implements ImageResolver {
        private final ObjectMap<String, Texture> images;

        public DirectImageResolver(ObjectMap<String, Texture> images) {
            this.images = images;
        }

        @Override // com.badlogic.gdx.maps.ImageResolver
        public TextureRegion getImage(String name) {
            return new TextureRegion(this.images.get(name));
        }
    }

    /* loaded from: classes.dex */
    public static class AssetManagerImageResolver implements ImageResolver {
        private final AssetManager assetManager;

        public AssetManagerImageResolver(AssetManager assetManager) {
            this.assetManager = assetManager;
        }

        @Override // com.badlogic.gdx.maps.ImageResolver
        public TextureRegion getImage(String name) {
            return new TextureRegion((Texture) this.assetManager.get(name, Texture.class));
        }
    }

    /* loaded from: classes.dex */
    public static class TextureAtlasImageResolver implements ImageResolver {
        private final TextureAtlas atlas;

        public TextureAtlasImageResolver(TextureAtlas atlas) {
            this.atlas = atlas;
        }

        @Override // com.badlogic.gdx.maps.ImageResolver
        public TextureRegion getImage(String name) {
            return this.atlas.findRegion(name);
        }
    }
}