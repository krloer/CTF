package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureArrayData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.nio.Buffer;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class TextureArray extends GLTexture {
    static final Map<Application, Array<TextureArray>> managedTextureArrays = new HashMap();
    private TextureArrayData data;

    public TextureArray(String... internalPaths) {
        this(getInternalHandles(internalPaths));
    }

    public TextureArray(FileHandle... files) {
        this(false, files);
    }

    public TextureArray(boolean useMipMaps, FileHandle... files) {
        this(useMipMaps, Pixmap.Format.RGBA8888, files);
    }

    public TextureArray(boolean useMipMaps, Pixmap.Format format, FileHandle... files) {
        this(TextureArrayData.Factory.loadFromFiles(format, useMipMaps, files));
    }

    public TextureArray(TextureArrayData data) {
        super(GL30.GL_TEXTURE_2D_ARRAY, Gdx.gl.glGenTexture());
        if (Gdx.gl30 == null) {
            throw new GdxRuntimeException("TextureArray requires a device running with GLES 3.0 compatibilty");
        }
        load(data);
        if (data.isManaged()) {
            addManagedTexture(Gdx.app, this);
        }
    }

    private static FileHandle[] getInternalHandles(String... internalPaths) {
        FileHandle[] handles = new FileHandle[internalPaths.length];
        for (int i = 0; i < internalPaths.length; i++) {
            handles[i] = Gdx.files.internal(internalPaths[i]);
        }
        return handles;
    }

    private void load(TextureArrayData data) {
        if (this.data != null && data.isManaged() != this.data.isManaged()) {
            throw new GdxRuntimeException("New data must have the same managed status as the old data");
        }
        this.data = data;
        bind();
        Gdx.gl30.glTexImage3D(GL30.GL_TEXTURE_2D_ARRAY, 0, data.getInternalFormat(), data.getWidth(), data.getHeight(), data.getDepth(), 0, data.getInternalFormat(), data.getGLType(), (Buffer) null);
        if (!data.isPrepared()) {
            data.prepare();
        }
        data.consumeTextureArrayData();
        setFilter(this.minFilter, this.magFilter);
        setWrap(this.uWrap, this.vWrap);
        Gdx.gl.glBindTexture(this.glTarget, 0);
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public int getWidth() {
        return this.data.getWidth();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public int getHeight() {
        return this.data.getHeight();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public int getDepth() {
        return this.data.getDepth();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public boolean isManaged() {
        return this.data.isManaged();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    protected void reload() {
        if (!isManaged()) {
            throw new GdxRuntimeException("Tried to reload an unmanaged TextureArray");
        }
        this.glHandle = Gdx.gl.glGenTexture();
        load(this.data);
    }

    private static void addManagedTexture(Application app, TextureArray texture) {
        Array<TextureArray> managedTextureArray = managedTextureArrays.get(app);
        if (managedTextureArray == null) {
            managedTextureArray = new Array<>();
        }
        managedTextureArray.add(texture);
        managedTextureArrays.put(app, managedTextureArray);
    }

    public static void clearAllTextureArrays(Application app) {
        managedTextureArrays.remove(app);
    }

    public static void invalidateAllTextureArrays(Application app) {
        Array<TextureArray> managedTextureArray = managedTextureArrays.get(app);
        if (managedTextureArray == null) {
            return;
        }
        for (int i = 0; i < managedTextureArray.size; i++) {
            TextureArray textureArray = managedTextureArray.get(i);
            textureArray.reload();
        }
    }

    public static String getManagedStatus() {
        StringBuilder builder = new StringBuilder();
        builder.append("Managed TextureArrays/app: { ");
        for (Application app : managedTextureArrays.keySet()) {
            builder.append(managedTextureArrays.get(app).size);
            builder.append(" ");
        }
        builder.append("}");
        return builder.toString();
    }

    public static int getNumManagedTextureArrays() {
        return managedTextureArrays.get(Gdx.app).size;
    }
}