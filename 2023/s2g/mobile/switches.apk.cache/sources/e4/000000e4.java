package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.CubemapLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.graphics.glutils.FacedCubemapData;
import com.badlogic.gdx.graphics.glutils.PixmapTextureData;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class Cubemap extends GLTexture {
    private static AssetManager assetManager;
    static final Map<Application, Array<Cubemap>> managedCubemaps = new HashMap();
    protected CubemapData data;

    /* loaded from: classes.dex */
    public enum CubemapSide {
        PositiveX(0, GL20.GL_TEXTURE_CUBE_MAP_POSITIVE_X, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f, 0.0f),
        NegativeX(1, GL20.GL_TEXTURE_CUBE_MAP_NEGATIVE_X, 0.0f, -1.0f, 0.0f, -1.0f, 0.0f, 0.0f),
        PositiveY(2, GL20.GL_TEXTURE_CUBE_MAP_POSITIVE_Y, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f),
        NegativeY(3, GL20.GL_TEXTURE_CUBE_MAP_NEGATIVE_Y, 0.0f, 0.0f, -1.0f, 0.0f, -1.0f, 0.0f),
        PositiveZ(4, GL20.GL_TEXTURE_CUBE_MAP_POSITIVE_Z, 0.0f, -1.0f, 0.0f, 0.0f, 0.0f, 1.0f),
        NegativeZ(5, GL20.GL_TEXTURE_CUBE_MAP_NEGATIVE_Z, 0.0f, -1.0f, 0.0f, 0.0f, 0.0f, -1.0f);
        
        public final Vector3 direction;
        public final int glEnum;
        public final int index;
        public final Vector3 up;

        CubemapSide(int index, int glEnum, float upX, float upY, float upZ, float directionX, float directionY, float directionZ) {
            this.index = index;
            this.glEnum = glEnum;
            this.up = new Vector3(upX, upY, upZ);
            this.direction = new Vector3(directionX, directionY, directionZ);
        }

        public int getGLEnum() {
            return this.glEnum;
        }

        public Vector3 getUp(Vector3 out) {
            return out.set(this.up);
        }

        public Vector3 getDirection(Vector3 out) {
            return out.set(this.direction);
        }
    }

    public Cubemap(CubemapData data) {
        super(GL20.GL_TEXTURE_CUBE_MAP);
        this.data = data;
        load(data);
        if (data.isManaged()) {
            addManagedCubemap(Gdx.app, this);
        }
    }

    public Cubemap(FileHandle positiveX, FileHandle negativeX, FileHandle positiveY, FileHandle negativeY, FileHandle positiveZ, FileHandle negativeZ) {
        this(positiveX, negativeX, positiveY, negativeY, positiveZ, negativeZ, false);
    }

    public Cubemap(FileHandle positiveX, FileHandle negativeX, FileHandle positiveY, FileHandle negativeY, FileHandle positiveZ, FileHandle negativeZ, boolean useMipMaps) {
        this(TextureData.Factory.loadFromFile(positiveX, useMipMaps), TextureData.Factory.loadFromFile(negativeX, useMipMaps), TextureData.Factory.loadFromFile(positiveY, useMipMaps), TextureData.Factory.loadFromFile(negativeY, useMipMaps), TextureData.Factory.loadFromFile(positiveZ, useMipMaps), TextureData.Factory.loadFromFile(negativeZ, useMipMaps));
    }

    public Cubemap(Pixmap positiveX, Pixmap negativeX, Pixmap positiveY, Pixmap negativeY, Pixmap positiveZ, Pixmap negativeZ) {
        this(positiveX, negativeX, positiveY, negativeY, positiveZ, negativeZ, false);
    }

    public Cubemap(Pixmap positiveX, Pixmap negativeX, Pixmap positiveY, Pixmap negativeY, Pixmap positiveZ, Pixmap negativeZ, boolean useMipMaps) {
        this(positiveX == null ? null : new PixmapTextureData(positiveX, null, useMipMaps, false), negativeX == null ? null : new PixmapTextureData(negativeX, null, useMipMaps, false), positiveY == null ? null : new PixmapTextureData(positiveY, null, useMipMaps, false), negativeY == null ? null : new PixmapTextureData(negativeY, null, useMipMaps, false), positiveZ == null ? null : new PixmapTextureData(positiveZ, null, useMipMaps, false), negativeZ == null ? null : new PixmapTextureData(negativeZ, null, useMipMaps, false));
    }

    public Cubemap(int width, int height, int depth, Pixmap.Format format) {
        this(new PixmapTextureData(new Pixmap(depth, height, format), null, false, true), new PixmapTextureData(new Pixmap(depth, height, format), null, false, true), new PixmapTextureData(new Pixmap(width, depth, format), null, false, true), new PixmapTextureData(new Pixmap(width, depth, format), null, false, true), new PixmapTextureData(new Pixmap(width, height, format), null, false, true), new PixmapTextureData(new Pixmap(width, height, format), null, false, true));
    }

    public Cubemap(TextureData positiveX, TextureData negativeX, TextureData positiveY, TextureData negativeY, TextureData positiveZ, TextureData negativeZ) {
        this(new FacedCubemapData(positiveX, negativeX, positiveY, negativeY, positiveZ, negativeZ));
    }

    public void load(CubemapData data) {
        if (!data.isPrepared()) {
            data.prepare();
        }
        bind();
        unsafeSetFilter(this.minFilter, this.magFilter, true);
        unsafeSetWrap(this.uWrap, this.vWrap, true);
        unsafeSetAnisotropicFilter(this.anisotropicFilterLevel, true);
        data.consumeCubemapData();
        Gdx.gl.glBindTexture(this.glTarget, 0);
    }

    public CubemapData getCubemapData() {
        return this.data;
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    public boolean isManaged() {
        return this.data.isManaged();
    }

    @Override // com.badlogic.gdx.graphics.GLTexture
    protected void reload() {
        if (!isManaged()) {
            throw new GdxRuntimeException("Tried to reload an unmanaged Cubemap");
        }
        this.glHandle = Gdx.gl.glGenTexture();
        load(this.data);
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

    @Override // com.badlogic.gdx.graphics.GLTexture, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.glHandle == 0) {
            return;
        }
        delete();
        if (!this.data.isManaged() || managedCubemaps.get(Gdx.app) == null) {
            return;
        }
        managedCubemaps.get(Gdx.app).removeValue(this, true);
    }

    private static void addManagedCubemap(Application app, Cubemap cubemap) {
        Array<Cubemap> managedCubemapArray = managedCubemaps.get(app);
        if (managedCubemapArray == null) {
            managedCubemapArray = new Array<>();
        }
        managedCubemapArray.add(cubemap);
        managedCubemaps.put(app, managedCubemapArray);
    }

    public static void clearAllCubemaps(Application app) {
        managedCubemaps.remove(app);
    }

    public static void invalidateAllCubemaps(Application app) {
        Array<Cubemap> managedCubemapArray = managedCubemaps.get(app);
        if (managedCubemapArray == null) {
            return;
        }
        AssetManager assetManager2 = assetManager;
        if (assetManager2 == null) {
            for (int i = 0; i < managedCubemapArray.size; i++) {
                managedCubemapArray.get(i).reload();
            }
            return;
        }
        assetManager2.finishLoading();
        Array<Cubemap> cubemaps = new Array<>(managedCubemapArray);
        Array.ArrayIterator<Cubemap> it = cubemaps.iterator();
        while (it.hasNext()) {
            Cubemap cubemap = it.next();
            String fileName = assetManager.getAssetFileName(cubemap);
            if (fileName == null) {
                cubemap.reload();
            } else {
                final int refCount = assetManager.getReferenceCount(fileName);
                assetManager.setReferenceCount(fileName, 0);
                cubemap.glHandle = 0;
                CubemapLoader.CubemapParameter params = new CubemapLoader.CubemapParameter();
                params.cubemapData = cubemap.getCubemapData();
                params.minFilter = cubemap.getMinFilter();
                params.magFilter = cubemap.getMagFilter();
                params.wrapU = cubemap.getUWrap();
                params.wrapV = cubemap.getVWrap();
                params.cubemap = cubemap;
                params.loadedCallback = new AssetLoaderParameters.LoadedCallback() { // from class: com.badlogic.gdx.graphics.Cubemap.1
                    @Override // com.badlogic.gdx.assets.AssetLoaderParameters.LoadedCallback
                    public void finishedLoading(AssetManager assetManager3, String fileName2, Class type) {
                        assetManager3.setReferenceCount(fileName2, refCount);
                    }
                };
                assetManager.unload(fileName);
                cubemap.glHandle = Gdx.gl.glGenTexture();
                assetManager.load(fileName, Cubemap.class, params);
            }
        }
        managedCubemapArray.clear();
        managedCubemapArray.addAll(cubemaps);
    }

    public static void setAssetManager(AssetManager manager) {
        assetManager = manager;
    }

    public static String getManagedStatus() {
        StringBuilder builder = new StringBuilder();
        builder.append("Managed cubemap/app: { ");
        for (Application app : managedCubemaps.keySet()) {
            builder.append(managedCubemaps.get(app).size);
            builder.append(" ");
        }
        builder.append("}");
        return builder.toString();
    }

    public static int getNumManagedCubemaps() {
        return managedCubemaps.get(Gdx.app).size;
    }
}