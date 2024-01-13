package com.badlogic.gdx.backends.android;

import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class AndroidFileHandle extends FileHandle {
    private final AssetManager assets;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AndroidFileHandle(AssetManager assets, String fileName, Files.FileType type) {
        super(fileName.replace('\\', '/'), type);
        this.assets = assets;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AndroidFileHandle(AssetManager assets, File file, Files.FileType type) {
        super(file, type);
        this.assets = assets;
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle child(String name) {
        String name2 = name.replace('\\', '/');
        return this.file.getPath().length() == 0 ? new AndroidFileHandle(this.assets, new File(name2), this.type) : new AndroidFileHandle(this.assets, new File(this.file, name2), this.type);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle sibling(String name) {
        String name2 = name.replace('\\', '/');
        if (this.file.getPath().length() == 0) {
            throw new GdxRuntimeException("Cannot get the sibling of the root.");
        }
        return Gdx.files.getFileHandle(new File(this.file.getParent(), name2).getPath(), this.type);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle parent() {
        File parent = this.file.getParentFile();
        if (parent == null) {
            if (this.type == Files.FileType.Absolute) {
                parent = new File("/");
            } else {
                parent = new File(BuildConfig.FLAVOR);
            }
        }
        return new AndroidFileHandle(this.assets, parent, this.type);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public InputStream read() {
        if (this.type == Files.FileType.Internal) {
            try {
                return this.assets.open(this.file.getPath());
            } catch (IOException ex) {
                throw new GdxRuntimeException("Error reading file: " + this.file + " (" + this.type + ")", ex);
            }
        }
        return super.read();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public ByteBuffer map(FileChannel.MapMode mode) {
        if (this.type == Files.FileType.Internal) {
            FileInputStream input = null;
            try {
                try {
                    AssetFileDescriptor fd = getAssetFileDescriptor();
                    long startOffset = fd.getStartOffset();
                    long declaredLength = fd.getDeclaredLength();
                    input = new FileInputStream(fd.getFileDescriptor());
                    ByteBuffer map = input.getChannel().map(mode, startOffset, declaredLength);
                    map.order(ByteOrder.nativeOrder());
                    return map;
                } catch (Exception ex) {
                    throw new GdxRuntimeException("Error memory mapping file: " + this + " (" + this.type + ")", ex);
                }
            } finally {
                StreamUtils.closeQuietly(input);
            }
        }
        return super.map(mode);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle[] list() {
        if (this.type == Files.FileType.Internal) {
            try {
                String[] relativePaths = this.assets.list(this.file.getPath());
                FileHandle[] handles = new FileHandle[relativePaths.length];
                int n = handles.length;
                for (int i = 0; i < n; i++) {
                    handles[i] = new AndroidFileHandle(this.assets, new File(this.file, relativePaths[i]), this.type);
                }
                return handles;
            } catch (Exception ex) {
                throw new GdxRuntimeException("Error listing children: " + this.file + " (" + this.type + ")", ex);
            }
        }
        return super.list();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(FileFilter filter) {
        if (this.type == Files.FileType.Internal) {
            try {
                String[] relativePaths = this.assets.list(this.file.getPath());
                FileHandle[] handles = new FileHandle[relativePaths.length];
                int count = 0;
                int n = handles.length;
                for (int i = 0; i < n; i++) {
                    String path = relativePaths[i];
                    FileHandle child = new AndroidFileHandle(this.assets, new File(this.file, path), this.type);
                    if (filter.accept(child.file())) {
                        handles[count] = child;
                        count++;
                    }
                }
                int i2 = relativePaths.length;
                if (count < i2) {
                    FileHandle[] newHandles = new FileHandle[count];
                    System.arraycopy(handles, 0, newHandles, 0, count);
                    return newHandles;
                }
                return handles;
            } catch (Exception ex) {
                throw new GdxRuntimeException("Error listing children: " + this.file + " (" + this.type + ")", ex);
            }
        }
        return super.list(filter);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(FilenameFilter filter) {
        if (this.type == Files.FileType.Internal) {
            try {
                String[] relativePaths = this.assets.list(this.file.getPath());
                FileHandle[] handles = new FileHandle[relativePaths.length];
                int count = 0;
                int n = handles.length;
                for (int i = 0; i < n; i++) {
                    String path = relativePaths[i];
                    if (filter.accept(this.file, path)) {
                        handles[count] = new AndroidFileHandle(this.assets, new File(this.file, path), this.type);
                        count++;
                    }
                }
                int i2 = relativePaths.length;
                if (count < i2) {
                    FileHandle[] newHandles = new FileHandle[count];
                    System.arraycopy(handles, 0, newHandles, 0, count);
                    return newHandles;
                }
                return handles;
            } catch (Exception ex) {
                throw new GdxRuntimeException("Error listing children: " + this.file + " (" + this.type + ")", ex);
            }
        }
        return super.list(filter);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public FileHandle[] list(String suffix) {
        if (this.type == Files.FileType.Internal) {
            try {
                String[] relativePaths = this.assets.list(this.file.getPath());
                FileHandle[] handles = new FileHandle[relativePaths.length];
                int count = 0;
                int n = handles.length;
                for (int i = 0; i < n; i++) {
                    String path = relativePaths[i];
                    if (path.endsWith(suffix)) {
                        handles[count] = new AndroidFileHandle(this.assets, new File(this.file, path), this.type);
                        count++;
                    }
                }
                int i2 = relativePaths.length;
                if (count < i2) {
                    FileHandle[] newHandles = new FileHandle[count];
                    System.arraycopy(handles, 0, newHandles, 0, count);
                    return newHandles;
                }
                return handles;
            } catch (Exception ex) {
                throw new GdxRuntimeException("Error listing children: " + this.file + " (" + this.type + ")", ex);
            }
        }
        return super.list(suffix);
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean isDirectory() {
        if (this.type == Files.FileType.Internal) {
            try {
                return this.assets.list(this.file.getPath()).length > 0;
            } catch (IOException e) {
                return false;
            }
        }
        return super.isDirectory();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public boolean exists() {
        if (this.type == Files.FileType.Internal) {
            String fileName = this.file.getPath();
            try {
                this.assets.open(fileName).close();
                return true;
            } catch (Exception e) {
                try {
                    return this.assets.list(fileName).length > 0;
                } catch (Exception e2) {
                    return false;
                }
            }
        }
        return super.exists();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public long length() {
        if (this.type == Files.FileType.Internal) {
            AssetFileDescriptor fileDescriptor = null;
            try {
                fileDescriptor = this.assets.openFd(this.file.getPath());
                long length = fileDescriptor.getLength();
                if (fileDescriptor != null) {
                    try {
                        fileDescriptor.close();
                    } catch (IOException e) {
                    }
                }
                return length;
            } catch (IOException e2) {
                if (fileDescriptor != null) {
                    try {
                        fileDescriptor.close();
                    } catch (IOException e3) {
                    }
                }
            } catch (Throwable th) {
                if (fileDescriptor != null) {
                    try {
                        fileDescriptor.close();
                    } catch (IOException e4) {
                    }
                }
                throw th;
            }
        }
        return super.length();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public long lastModified() {
        return super.lastModified();
    }

    @Override // com.badlogic.gdx.files.FileHandle
    public File file() {
        return this.type == Files.FileType.Local ? new File(Gdx.files.getLocalStoragePath(), this.file.getPath()) : super.file();
    }

    public AssetFileDescriptor getAssetFileDescriptor() throws IOException {
        AssetManager assetManager = this.assets;
        if (assetManager != null) {
            return assetManager.openFd(path());
        }
        return null;
    }
}