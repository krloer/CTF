package com.badlogic.gdx.backends.android;

import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.backends.android.ZipResourceFile;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class AndroidZipFileHandle extends AndroidFileHandle {
    private ZipResourceFile expansionFile;
    private long fdLength;
    private boolean hasAssetFd;
    private String path;

    public AndroidZipFileHandle(String fileName) {
        super((AssetManager) null, fileName, Files.FileType.Internal);
        initialize();
    }

    public AndroidZipFileHandle(File file, Files.FileType type) {
        super((AssetManager) null, file, type);
        initialize();
    }

    private void initialize() {
        this.path = this.file.getPath().replace('\\', '/');
        this.expansionFile = ((AndroidFiles) Gdx.files).getExpansionFile();
        AssetFileDescriptor assetFd = this.expansionFile.getAssetFileDescriptor(getPath());
        if (assetFd != null) {
            this.hasAssetFd = true;
            this.fdLength = assetFd.getLength();
            try {
                assetFd.close();
            } catch (IOException e) {
            }
        } else {
            this.hasAssetFd = false;
        }
        if (isDirectory()) {
            this.path += "/";
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle
    public AssetFileDescriptor getAssetFileDescriptor() throws IOException {
        return this.expansionFile.getAssetFileDescriptor(getPath());
    }

    private String getPath() {
        return this.path;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public InputStream read() {
        try {
            InputStream input = this.expansionFile.getInputStream(getPath());
            return input;
        } catch (IOException ex) {
            throw new GdxRuntimeException("Error reading file: " + this.file + " (ZipResourceFile)", ex);
        }
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle child(String name) {
        if (this.file.getPath().length() == 0) {
            return new AndroidZipFileHandle(new File(name), this.type);
        }
        return new AndroidZipFileHandle(new File(this.file, name), this.type);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle sibling(String name) {
        if (this.file.getPath().length() == 0) {
            throw new GdxRuntimeException("Cannot get the sibling of the root.");
        }
        return Gdx.files.getFileHandle(new File(this.file.getParent(), name).getPath(), this.type);
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle parent() {
        File parent = this.file.getParentFile();
        if (parent == null) {
            parent = new File(BuildConfig.FLAVOR);
        }
        return new AndroidZipFileHandle(parent.getPath());
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle[] list() {
        ZipResourceFile.ZipEntryRO[] zipEntries = this.expansionFile.getEntriesAt(getPath());
        FileHandle[] handles = new FileHandle[zipEntries.length - 1];
        int count = 0;
        int n = zipEntries.length;
        for (int i = 0; i < n; i++) {
            if (zipEntries[i].mFileName.length() != getPath().length()) {
                handles[count] = new AndroidZipFileHandle(zipEntries[i].mFileName);
                count++;
            }
        }
        return handles;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(FileFilter filter) {
        ZipResourceFile.ZipEntryRO[] zipEntries = this.expansionFile.getEntriesAt(getPath());
        FileHandle[] handles = new FileHandle[zipEntries.length - 1];
        int count = 0;
        int n = zipEntries.length;
        for (int i = 0; i < n; i++) {
            if (zipEntries[i].mFileName.length() != getPath().length()) {
                FileHandle child = new AndroidZipFileHandle(zipEntries[i].mFileName);
                if (filter.accept(child.file())) {
                    handles[count] = child;
                    count++;
                }
            }
        }
        int i2 = handles.length;
        if (count < i2) {
            FileHandle[] newHandles = new FileHandle[count];
            System.arraycopy(handles, 0, newHandles, 0, count);
            return newHandles;
        }
        return handles;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(FilenameFilter filter) {
        ZipResourceFile.ZipEntryRO[] zipEntries = this.expansionFile.getEntriesAt(getPath());
        FileHandle[] handles = new FileHandle[zipEntries.length - 1];
        int count = 0;
        int n = zipEntries.length;
        for (int i = 0; i < n; i++) {
            if (zipEntries[i].mFileName.length() != getPath().length()) {
                String path = zipEntries[i].mFileName;
                if (filter.accept(this.file, path)) {
                    handles[count] = new AndroidZipFileHandle(path);
                    count++;
                }
            }
        }
        int i2 = handles.length;
        if (count < i2) {
            FileHandle[] newHandles = new FileHandle[count];
            System.arraycopy(handles, 0, newHandles, 0, count);
            return newHandles;
        }
        return handles;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(String suffix) {
        ZipResourceFile.ZipEntryRO[] zipEntries = this.expansionFile.getEntriesAt(getPath());
        FileHandle[] handles = new FileHandle[zipEntries.length - 1];
        int count = 0;
        int n = zipEntries.length;
        for (int i = 0; i < n; i++) {
            if (zipEntries[i].mFileName.length() != getPath().length()) {
                String path = zipEntries[i].mFileName;
                if (path.endsWith(suffix)) {
                    handles[count] = new AndroidZipFileHandle(path);
                    count++;
                }
            }
        }
        int i2 = handles.length;
        if (count < i2) {
            FileHandle[] newHandles = new FileHandle[count];
            System.arraycopy(handles, 0, newHandles, 0, count);
            return newHandles;
        }
        return handles;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public boolean isDirectory() {
        return !this.hasAssetFd;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public long length() {
        if (this.hasAssetFd) {
            return this.fdLength;
        }
        return 0L;
    }

    @Override // com.badlogic.gdx.backends.android.AndroidFileHandle, com.badlogic.gdx.files.FileHandle
    public boolean exists() {
        return this.hasAssetFd || this.expansionFile.getEntriesAt(getPath()).length != 0;
    }
}