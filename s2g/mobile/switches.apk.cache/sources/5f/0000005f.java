package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class BitmapFontLoader extends AsynchronousAssetLoader<BitmapFont, BitmapFontParameter> {
    BitmapFont.BitmapFontData data;

    /* loaded from: classes.dex */
    public static class BitmapFontParameter extends AssetLoaderParameters<BitmapFont> {
        public boolean flip = false;
        public boolean genMipMaps = false;
        public Texture.TextureFilter minFilter = Texture.TextureFilter.Nearest;
        public Texture.TextureFilter magFilter = Texture.TextureFilter.Nearest;
        public BitmapFont.BitmapFontData bitmapFontData = null;
        public String atlasName = null;
    }

    public BitmapFontLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, BitmapFontParameter parameter) {
        Array<AssetDescriptor> deps = new Array<>();
        if (parameter != null && parameter.bitmapFontData != null) {
            this.data = parameter.bitmapFontData;
            return deps;
        }
        this.data = new BitmapFont.BitmapFontData(file, parameter != null && parameter.flip);
        if (parameter != null && parameter.atlasName != null) {
            deps.add(new AssetDescriptor(parameter.atlasName, TextureAtlas.class));
        } else {
            for (int i = 0; i < this.data.getImagePaths().length; i++) {
                String path = this.data.getImagePath(i);
                FileHandle resolved = resolve(path);
                TextureLoader.TextureParameter textureParams = new TextureLoader.TextureParameter();
                if (parameter != null) {
                    textureParams.genMipMaps = parameter.genMipMaps;
                    textureParams.minFilter = parameter.minFilter;
                    textureParams.magFilter = parameter.magFilter;
                }
                AssetDescriptor descriptor = new AssetDescriptor(resolved, Texture.class, textureParams);
                deps.add(descriptor);
            }
        }
        return deps;
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, BitmapFontParameter parameter) {
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public BitmapFont loadSync(AssetManager manager, String fileName, FileHandle file, BitmapFontParameter parameter) {
        if (parameter != null && parameter.atlasName != null) {
            TextureAtlas atlas = (TextureAtlas) manager.get(parameter.atlasName, TextureAtlas.class);
            String name = file.sibling(this.data.imagePaths[0]).nameWithoutExtension().toString();
            TextureAtlas.AtlasRegion region = atlas.findRegion(name);
            if (region == null) {
                throw new GdxRuntimeException("Could not find font region " + name + " in atlas " + parameter.atlasName);
            }
            return new BitmapFont(file, region);
        }
        int n = this.data.getImagePaths().length;
        Array<TextureRegion> regs = new Array<>(n);
        for (int i = 0; i < n; i++) {
            regs.add(new TextureRegion((Texture) manager.get(this.data.getImagePath(i), Texture.class)));
        }
        return new BitmapFont(this.data, regs, true);
    }
}