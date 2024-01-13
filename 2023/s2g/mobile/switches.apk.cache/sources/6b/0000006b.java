package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g2d.ParticleEffect;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class ParticleEffectLoader extends SynchronousAssetLoader<ParticleEffect, ParticleEffectParameter> {

    /* loaded from: classes.dex */
    public static class ParticleEffectParameter extends AssetLoaderParameters<ParticleEffect> {
        public String atlasFile;
        public String atlasPrefix;
        public FileHandle imagesDir;
    }

    public ParticleEffectLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.SynchronousAssetLoader
    public ParticleEffect load(AssetManager am, String fileName, FileHandle file, ParticleEffectParameter param) {
        ParticleEffect effect = new ParticleEffect();
        if (param != null && param.atlasFile != null) {
            effect.load(file, (TextureAtlas) am.get(param.atlasFile, TextureAtlas.class), param.atlasPrefix);
        } else if (param != null && param.imagesDir != null) {
            effect.load(file, param.imagesDir);
        } else {
            effect.load(file, file.parent());
        }
        return effect;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, ParticleEffectParameter param) {
        if (param == null || param.atlasFile == null) {
            return null;
        }
        Array<AssetDescriptor> deps = new Array<>();
        deps.add(new AssetDescriptor(param.atlasFile, TextureAtlas.class));
        return deps;
    }
}