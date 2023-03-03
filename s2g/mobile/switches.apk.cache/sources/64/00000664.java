package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.files.FileHandle;
import com.kotcrab.vis.ui.widget.file.FileUtils;

/* loaded from: classes.dex */
public class FileHandleMetadata {
    private final boolean directory;
    private final long lastModified;
    private final long length;
    private final String name;
    private final String readableFileSize;

    public static FileHandleMetadata of(FileHandle file) {
        return new FileHandleMetadata(file);
    }

    private FileHandleMetadata(FileHandle file) {
        this.name = file.name();
        this.directory = file.isDirectory();
        this.lastModified = file.lastModified();
        this.length = file.length();
        this.readableFileSize = FileUtils.readableFileSize(this.length);
    }

    public String name() {
        return this.name;
    }

    public boolean isDirectory() {
        return this.directory;
    }

    public long lastModified() {
        return this.lastModified;
    }

    public long length() {
        return this.length;
    }

    public String readableFileSize() {
        return this.readableFileSize;
    }
}