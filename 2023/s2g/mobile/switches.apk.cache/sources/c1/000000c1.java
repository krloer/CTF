package com.badlogic.gdx.backends.android;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.AssetManager;
import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.io.File;
import java.io.IOException;

/* loaded from: classes.dex */
public class DefaultAndroidFiles implements AndroidFiles {
    protected final AssetManager assets;
    private ZipResourceFile expansionFile = null;
    protected final String externalFilesPath;
    protected final String localpath;

    public DefaultAndroidFiles(AssetManager assets, ContextWrapper contextWrapper, boolean useExternalFiles) {
        String str;
        this.assets = assets;
        String localPath = contextWrapper.getFilesDir().getAbsolutePath();
        if (localPath.endsWith("/")) {
            str = localPath;
        } else {
            str = localPath + "/";
        }
        this.localpath = str;
        if (useExternalFiles) {
            this.externalFilesPath = initExternalFilesPath(contextWrapper);
        } else {
            this.externalFilesPath = null;
        }
    }

    protected String initExternalFilesPath(ContextWrapper contextWrapper) {
        File externalFilesDir = contextWrapper.getExternalFilesDir(null);
        if (externalFilesDir == null) {
            return null;
        }
        String externalFilesPath = externalFilesDir.getAbsolutePath();
        if (externalFilesPath.endsWith("/")) {
            return externalFilesPath;
        }
        return externalFilesPath + "/";
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle getFileHandle(String path, Files.FileType type) {
        FileHandle handle = new AndroidFileHandle(type == Files.FileType.Internal ? this.assets : null, path, type);
        return (this.expansionFile == null || type != Files.FileType.Internal) ? handle : getZipFileHandleIfExists(handle, path);
    }

    private FileHandle getZipFileHandleIfExists(FileHandle handle, String path) {
        try {
            this.assets.open(path).close();
            return handle;
        } catch (Exception e) {
            FileHandle zipHandle = new AndroidZipFileHandle(path);
            if (zipHandle.isDirectory()) {
                return zipHandle.exists() ? zipHandle : handle;
            }
            return zipHandle;
        }
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle classpath(String path) {
        return new AndroidFileHandle((AssetManager) null, path, Files.FileType.Classpath);
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle internal(String path) {
        FileHandle handle = new AndroidFileHandle(this.assets, path, Files.FileType.Internal);
        return this.expansionFile != null ? getZipFileHandleIfExists(handle, path) : handle;
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle external(String path) {
        return new AndroidFileHandle((AssetManager) null, path, Files.FileType.External);
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle absolute(String path) {
        return new AndroidFileHandle((AssetManager) null, path, Files.FileType.Absolute);
    }

    @Override // com.badlogic.gdx.Files
    public FileHandle local(String path) {
        return new AndroidFileHandle((AssetManager) null, path, Files.FileType.Local);
    }

    @Override // com.badlogic.gdx.Files
    public String getExternalStoragePath() {
        return this.externalFilesPath;
    }

    @Override // com.badlogic.gdx.Files
    public boolean isExternalStorageAvailable() {
        return this.externalFilesPath != null;
    }

    @Override // com.badlogic.gdx.Files
    public String getLocalStoragePath() {
        return this.localpath;
    }

    @Override // com.badlogic.gdx.Files
    public boolean isLocalStorageAvailable() {
        return true;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFiles
    public boolean setAPKExpansion(int mainVersion, int patchVersion) {
        Context context;
        try {
            if (Gdx.app instanceof Activity) {
                context = ((Activity) Gdx.app).getBaseContext();
            } else if (Gdx.app instanceof Fragment) {
                context = ((Fragment) Gdx.app).getActivity().getBaseContext();
            } else {
                throw new GdxRuntimeException("APK expansion not supported for application type");
            }
            this.expansionFile = APKExpansionSupport.getAPKExpansionZipFile(context, mainVersion, patchVersion);
            return this.expansionFile != null;
        } catch (IOException e) {
            throw new GdxRuntimeException("APK expansion main version " + mainVersion + " or patch version " + patchVersion + " couldn't be opened!");
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFiles
    public ZipResourceFile getExpansionFile() {
        return this.expansionFile;
    }
}