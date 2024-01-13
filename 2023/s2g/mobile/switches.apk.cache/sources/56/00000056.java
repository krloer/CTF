package com.badlogic.gdx.assets;

import com.badlogic.gdx.files.FileHandle;

/* loaded from: classes.dex */
public class AssetDescriptor<T> {
    public FileHandle file;
    public final String fileName;
    public final AssetLoaderParameters params;
    public final Class<T> type;

    public AssetDescriptor(String fileName, Class<T> assetType) {
        this(fileName, assetType, (AssetLoaderParameters) null);
    }

    public AssetDescriptor(FileHandle file, Class<T> assetType) {
        this(file, assetType, (AssetLoaderParameters) null);
    }

    public AssetDescriptor(String fileName, Class<T> assetType, AssetLoaderParameters<T> params) {
        this.fileName = fileName.replace('\\', '/');
        this.type = assetType;
        this.params = params;
    }

    public AssetDescriptor(FileHandle file, Class<T> assetType, AssetLoaderParameters<T> params) {
        this.fileName = file.path().replace('\\', '/');
        this.file = file;
        this.type = assetType;
        this.params = params;
    }

    public String toString() {
        return this.fileName + ", " + this.type.getName();
    }
}