package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class PixmapLoader extends AsynchronousAssetLoader<Pixmap, PixmapParameter> {
    Pixmap pixmap;

    /* loaded from: classes.dex */
    public static class PixmapParameter extends AssetLoaderParameters<Pixmap> {
    }

    public PixmapLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, PixmapParameter parameter) {
        this.pixmap = null;
        this.pixmap = new Pixmap(file);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public Pixmap loadSync(AssetManager manager, String fileName, FileHandle file, PixmapParameter parameter) {
        Pixmap pixmap = this.pixmap;
        this.pixmap = null;
        return pixmap;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, PixmapParameter parameter) {
        return null;
    }
}