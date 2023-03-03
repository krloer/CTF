package com.badlogic.gdx.assets;

import com.badlogic.gdx.assets.loaders.AssetLoader;
import com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader;
import com.badlogic.gdx.assets.loaders.SynchronousAssetLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.TimeUtils;
import com.badlogic.gdx.utils.async.AsyncExecutor;
import com.badlogic.gdx.utils.async.AsyncResult;
import com.badlogic.gdx.utils.async.AsyncTask;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class AssetLoadingTask implements AsyncTask<Void> {
    volatile Object asset;
    final AssetDescriptor assetDesc;
    volatile boolean asyncDone;
    volatile boolean cancel;
    volatile Array<AssetDescriptor> dependencies;
    volatile boolean dependenciesLoaded;
    volatile AsyncResult<Void> depsFuture;
    final AsyncExecutor executor;
    volatile AsyncResult<Void> loadFuture;
    final AssetLoader loader;
    AssetManager manager;
    final long startTime;

    public AssetLoadingTask(AssetManager manager, AssetDescriptor assetDesc, AssetLoader loader, AsyncExecutor threadPool) {
        this.manager = manager;
        this.assetDesc = assetDesc;
        this.loader = loader;
        this.executor = threadPool;
        this.startTime = manager.log.getLevel() == 3 ? TimeUtils.nanoTime() : 0L;
    }

    @Override // com.badlogic.gdx.utils.async.AsyncTask
    public Void call() throws Exception {
        if (this.cancel) {
            return null;
        }
        AsynchronousAssetLoader asyncLoader = (AsynchronousAssetLoader) this.loader;
        if (!this.dependenciesLoaded) {
            this.dependencies = asyncLoader.getDependencies(this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
            if (this.dependencies != null) {
                removeDuplicates(this.dependencies);
                this.manager.injectDependencies(this.assetDesc.fileName, this.dependencies);
            } else {
                asyncLoader.loadAsync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
                this.asyncDone = true;
            }
        } else {
            asyncLoader.loadAsync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
            this.asyncDone = true;
        }
        return null;
    }

    public boolean update() {
        if (this.loader instanceof SynchronousAssetLoader) {
            handleSyncLoader();
        } else {
            handleAsyncLoader();
        }
        return this.asset != null;
    }

    private void handleSyncLoader() {
        SynchronousAssetLoader syncLoader = (SynchronousAssetLoader) this.loader;
        if (!this.dependenciesLoaded) {
            this.dependenciesLoaded = true;
            this.dependencies = syncLoader.getDependencies(this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
            if (this.dependencies == null) {
                this.asset = syncLoader.load(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
                return;
            }
            removeDuplicates(this.dependencies);
            this.manager.injectDependencies(this.assetDesc.fileName, this.dependencies);
            return;
        }
        this.asset = syncLoader.load(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
    }

    private void handleAsyncLoader() {
        AsynchronousAssetLoader asyncLoader = (AsynchronousAssetLoader) this.loader;
        if (!this.dependenciesLoaded) {
            if (this.depsFuture == null) {
                this.depsFuture = this.executor.submit(this);
            } else if (this.depsFuture.isDone()) {
                try {
                    this.depsFuture.get();
                    this.dependenciesLoaded = true;
                    if (this.asyncDone) {
                        this.asset = asyncLoader.loadSync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
                    }
                } catch (Exception e) {
                    throw new GdxRuntimeException("Couldn't load dependencies of asset: " + this.assetDesc.fileName, e);
                }
            }
        } else if (this.loadFuture == null && !this.asyncDone) {
            this.loadFuture = this.executor.submit(this);
        } else if (this.asyncDone) {
            this.asset = asyncLoader.loadSync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
        } else if (this.loadFuture.isDone()) {
            try {
                this.loadFuture.get();
                this.asset = asyncLoader.loadSync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
            } catch (Exception e2) {
                throw new GdxRuntimeException("Couldn't load asset: " + this.assetDesc.fileName, e2);
            }
        }
    }

    public void unload() {
        AssetLoader assetLoader = this.loader;
        if (assetLoader instanceof AsynchronousAssetLoader) {
            ((AsynchronousAssetLoader) assetLoader).unloadAsync(this.manager, this.assetDesc.fileName, resolve(this.loader, this.assetDesc), this.assetDesc.params);
        }
    }

    private FileHandle resolve(AssetLoader loader, AssetDescriptor assetDesc) {
        if (assetDesc.file == null) {
            assetDesc.file = loader.resolve(assetDesc.fileName);
        }
        return assetDesc.file;
    }

    private void removeDuplicates(Array<AssetDescriptor> array) {
        boolean ordered = array.ordered;
        array.ordered = true;
        for (int i = 0; i < array.size; i++) {
            String fn = array.get(i).fileName;
            Class type = array.get(i).type;
            for (int j = array.size - 1; j > i; j--) {
                if (type == array.get(j).type && fn.equals(array.get(j).fileName)) {
                    array.removeIndex(j);
                }
            }
        }
        array.ordered = ordered;
    }
}