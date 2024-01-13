package com.badlogic.gdx.assets.loaders;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.audio.Music;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class MusicLoader extends AsynchronousAssetLoader<Music, MusicParameter> {
    private Music music;

    /* loaded from: classes.dex */
    public static class MusicParameter extends AssetLoaderParameters<Music> {
    }

    public MusicLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    protected Music getLoadedMusic() {
        return this.music;
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle file, MusicParameter parameter) {
        this.music = Gdx.audio.newMusic(file);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public Music loadSync(AssetManager manager, String fileName, FileHandle file, MusicParameter parameter) {
        Music music = this.music;
        this.music = null;
        return music;
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, MusicParameter parameter) {
        return null;
    }
}