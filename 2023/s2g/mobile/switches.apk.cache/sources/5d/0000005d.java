package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public abstract class AssetLoader<T, P extends AssetLoaderParameters<T>> {
    private FileHandleResolver resolver;

    public abstract Array<AssetDescriptor> getDependencies(String str, FileHandle fileHandle, P p);

    public AssetLoader(FileHandleResolver resolver) {
        this.resolver = resolver;
    }

    public FileHandle resolve(String fileName) {
        return this.resolver.resolve(fileName);
    }
}