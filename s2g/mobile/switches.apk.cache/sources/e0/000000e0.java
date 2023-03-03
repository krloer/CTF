package com.badlogic.gdx.files;

import com.badlogic.gdx.Files;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes.dex */
public abstract class FileHandleStream extends FileHandle {
    public FileHandleStream(String path) {
        super(new File(path), Files.FileType.Absolute);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean isDirectory() {
        return false;
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public long length() {
        return 0L;
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean exists() {
        return true;
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle child(String name) {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle sibling(String name) {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle parent() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public InputStream read() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public OutputStream write(boolean overwrite) {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle[] list() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public void mkdirs() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean delete() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean deleteDirectory() {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public void copyTo(FileHandle dest) {
        throw new UnsupportedOperationException();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public void moveTo(FileHandle dest) {
        throw new UnsupportedOperationException();
    }
}