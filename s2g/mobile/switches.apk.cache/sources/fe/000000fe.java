package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.graphics.glutils.FileTextureData;
import com.badlogic.gdx.graphics.glutils.PixmapTextureData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class Texture extends GLTexture {
    private static AssetManager assetManager;
    static final Map<Application, Array<Texture>> managedTextures = new HashMap();
    TextureData data;

    /* loaded from: classes.dex */
    public enum TextureFilter {
        Nearest(GL20.GL_NEAREST),
        Linear(GL20.GL_LINEAR),
        MipMap(GL20.GL_LINEAR_MIPMAP_LINEAR),
        MipMapNearestNearest(GL20.GL_NEAREST_MIPMAP_NEAREST),
        MipMapLinearNearest(GL20.GL_LINEAR_MIPMAP_NEAREST),
        MipMapNearestLinear(GL20.GL_NEAREST_MIPMAP_LINEAR),
        MipMapLinearLinear(GL20.GL_LINEAR_MIPMAP_LINEAR);
        
        final int glEnum;

        TextureFilter(int glEnum) {
            this.glEnum = glEnum;
        }

        public boolean isMipMap() {
            int i = this.glEnum;
            return (i == 9728 || i == 9729) ? false : true;
        }

        public int getGLEnum() {
            return this.glEnum;
        }
    }

    /* loaded from: classes.dex */
    public enum TextureWrap {
        MirroredRepeat(GL20.GL_MIRRORED_REPEAT),
        ClampToEdge(GL20.GL_CLAMP_TO_EDGE),
        Repeat(GL20.GL_REPEAT);
        
        final int glEnum;

        TextureWrap(int glEnum) {
            this.glEnum = glEnum;
        }

        public int getGLEnum() {
            return this.glEnum;
        }
    }

    public Texture(String internalPath) {
        this(Gdx.files.internal(internalPath));
    }

    public Texture(FileHandle file) {
        this(file, (Pixmap.Format) null, false);
    }

    public Texture(FileHandle file, boolean useMipMaps) {
        this(file, (Pixmap.Format) null, useMipMaps);
    }

    public Texture(FileHandle file, Pixmap.Format format, boolean useMipMaps) {
        this(TextureData.Factory.loadFromFile(file, format, useMipMaps));
    }

    public Texture(Pixmap pixmap) {
        this(new PixmapTextureData(pixmap, null, false, false));
    }

    public Texture(Pixmap pixmap, boolean useMipMaps) {
        this(new PixmapTextureData(pixmap, null, useMipMaps, false));
    }

    public Texture(Pixmap pixmap, Pixmap.Format format, boolean useMipMaps) {
        this(new PixmapTextureData(pixmap, format, useMipMaps, false));
    }

    public Texture(int width, int height, Pixmap.Format format) {
        this(new PixmapTextureData(new Pixmap(width, height, format), null, false, true));
    }

    public Texture(TextureData data) {
        this((int) GL20.GL_TEXTURE_2D, Gdx.gl.glGenTexture(), data);
    }

    protected Texture(int glTarget, int glHandle, TextureData data) {
        super(glTarget, glHandle);
        load(data);
        if (data.isManaged()) {
            addManagedTexture(Gdx.app, this);
        }
    }

    public void load(TextureData data) {
        if (this.data != null && data.isManaged() != this.data.isManaged()) {
            throw new GdxRuntimeException("New data must have the same managed status as the old data");
        }
        this.data = data;
        if (!data.isPrepared()) {
            data.prepare();
        }
        bind();
        uploadImageData(GL20.GL_TEXTURE_2D, data);
        unsafeSetFilter(this.minFilter, this.magFilter, true);
        unsafeSetWrap(this.uWrap, this.vWrap, true);
        unsafeSetAnisotropicFilter(this.anisotropicFilterLevel, true);
        Gdx.gl.glBindTexture(this.glTarget, 0);
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    protected void reload() {
        if (!isManaged()) {
            throw new GdxRuntimeException("Tried to reload unmanaged Texture");
        }
        this.glHandle = Gdx.gl.glGenTexture();
        load(this.data);
    }

    public void draw(Pixmap pixmap, int x, int y) {
        if (this.data.isManaged()) {
            throw new GdxRuntimeException("can't draw to a managed texture");
        }
        bind();
        Gdx.gl.glTexSubImage2D(this.glTarget, 0, x, y, pixmap.getWidth(), pixmap.getHeight(), pixmap.getGLFormat(), pixmap.getGLType(), pixmap.getPixels());
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
        return 0;
    }

    public TextureData getTextureData() {
        return this.data;
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public boolean isManaged() {
        return this.data.isManaged();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.glHandle == 0) {
            return;
        }
        delete();
        if (!this.data.isManaged() || managedTextures.get(Gdx.app) == null) {
            return;
        }
        managedTextures.get(Gdx.app).removeValue(this, true);
    }

    public String toString() {
        TextureData textureData = this.data;
        return textureData instanceof FileTextureData ? textureData.toString() : super.toString();
    }

    private static void addManagedTexture(Application app, Texture texture) {
        Array<Texture> managedTextureArray = managedTextures.get(app);
        if (managedTextureArray == null) {
            managedTextureArray = new Array<>();
        }
        managedTextureArray.add(texture);
        managedTextures.put(app, managedTextureArray);
    }

    public static void clearAllTextures(Application app) {
        managedTextures.remove(app);
    }

    public static void invalidateAllTextures(Application app) {
        Array<Texture> managedTextureArray = managedTextures.get(app);
        if (managedTextureArray == null) {
            return;
        }
        AssetManager assetManager2 = assetManager;
        if (assetManager2 == null) {
            for (int i = 0; i < managedTextureArray.size; i++) {
                managedTextureArray.get(i).reload();
            }
            return;
        }
        assetManager2.finishLoading();
        Array<Texture> textures = new Array<>(managedTextureArray);
        Array.ArrayIterator<Texture> it = textures.iterator();
        while (it.hasNext()) {
            Texture texture = it.next();
            String fileName = assetManager.getAssetFileName(texture);
            if (fileName == null) {
                texture.reload();
            } else {
                final int refCount = assetManager.getReferenceCount(fileName);
                assetManager.setReferenceCount(fileName, 0);
                texture.glHandle = 0;
                TextureLoader.TextureParameter params = new TextureLoader.TextureParameter();
                params.textureData = texture.getTextureData();
                params.minFilter = texture.getMinFilter();
                params.magFilter = texture.getMagFilter();
                params.wrapU = texture.getUWrap();
                params.wrapV = texture.getVWrap();
                params.genMipMaps = texture.data.useMipMaps();
                params.texture = texture;
                params.loadedCallback = new AssetLoaderParameters.LoadedCallback() { // from class: com.badlogic.gdx.graphics.Texture.1
                    @Override // com.badlogic.gdx.assets.AssetLoaderParameters.LoadedCallback
                    public void finishedLoading(AssetManager assetManager3, String fileName2, Class type) {
                        assetManager3.setReferenceCount(fileName2, refCount);
                    }
                };
                assetManager.unload(fileName);
                texture.glHandle = Gdx.gl.glGenTexture();
                assetManager.load(fileName, Texture.class, params);
            }
        }
        managedTextureArray.clear();
        managedTextureArray.addAll(textures);
    }

    public static void setAssetManager(AssetManager manager) {
        assetManager = manager;
    }

    public static String getManagedStatus() {
        StringBuilder builder = new StringBuilder();
        builder.append("Managed textures/app: { ");
        for (Application app : managedTextures.keySet()) {
            builder.append(managedTextures.get(app).size);
            builder.append(" ");
        }
        builder.append("}");
        return builder.toString();
    }

    public static int getNumManagedTextures() {
        return managedTextures.get(Gdx.app).size;
    }
}