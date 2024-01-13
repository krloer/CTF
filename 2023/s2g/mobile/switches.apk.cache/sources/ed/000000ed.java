package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.graphics.glutils.MipMapGenerator;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.Disposable;
import java.nio.FloatBuffer;

/* loaded from: classes.dex */
public abstract class GLTexture implements Disposable {
    private static float maxAnisotropicFilterLevel = 0.0f;
    protected float anisotropicFilterLevel;
    protected int glHandle;
    public final int glTarget;
    protected Texture.TextureFilter magFilter;
    protected Texture.TextureFilter minFilter;
    protected Texture.TextureWrap uWrap;
    protected Texture.TextureWrap vWrap;

    public abstract int getDepth();

    public abstract int getHeight();

    public abstract int getWidth();

    public abstract boolean isManaged();

    protected abstract void reload();

    public GLTexture(int glTarget) {
        this(glTarget, Gdx.gl.glGenTexture());
    }

    public GLTexture(int glTarget, int glHandle) {
        this.minFilter = Texture.TextureFilter.Nearest;
        this.magFilter = Texture.TextureFilter.Nearest;
        this.uWrap = Texture.TextureWrap.ClampToEdge;
        this.vWrap = Texture.TextureWrap.ClampToEdge;
        this.anisotropicFilterLevel = 1.0f;
        this.glTarget = glTarget;
        this.glHandle = glHandle;
    }

    public void bind() {
        Gdx.gl.glBindTexture(this.glTarget, this.glHandle);
    }

    public void bind(int unit) {
        Gdx.gl.glActiveTexture(GL20.GL_TEXTURE0 + unit);
        Gdx.gl.glBindTexture(this.glTarget, this.glHandle);
    }

    public Texture.TextureFilter getMinFilter() {
        return this.minFilter;
    }

    public Texture.TextureFilter getMagFilter() {
        return this.magFilter;
    }

    public Texture.TextureWrap getUWrap() {
        return this.uWrap;
    }

    public Texture.TextureWrap getVWrap() {
        return this.vWrap;
    }

    public int getTextureObjectHandle() {
        return this.glHandle;
    }

    public void unsafeSetWrap(Texture.TextureWrap u, Texture.TextureWrap v) {
        unsafeSetWrap(u, v, false);
    }

    public void unsafeSetWrap(Texture.TextureWrap u, Texture.TextureWrap v, boolean force) {
        if (u != null && (force || this.uWrap != u)) {
            Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_WRAP_S, u.getGLEnum());
            this.uWrap = u;
        }
        if (v != null) {
            if (force || this.vWrap != v) {
                Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_WRAP_T, v.getGLEnum());
                this.vWrap = v;
            }
        }
    }

    public void setWrap(Texture.TextureWrap u, Texture.TextureWrap v) {
        this.uWrap = u;
        this.vWrap = v;
        bind();
        Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_WRAP_S, u.getGLEnum());
        Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_WRAP_T, v.getGLEnum());
    }

    public void unsafeSetFilter(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter) {
        unsafeSetFilter(minFilter, magFilter, false);
    }

    public void unsafeSetFilter(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean force) {
        if (minFilter != null && (force || this.minFilter != minFilter)) {
            Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_MIN_FILTER, minFilter.getGLEnum());
            this.minFilter = minFilter;
        }
        if (magFilter != null) {
            if (force || this.magFilter != magFilter) {
                Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_MAG_FILTER, magFilter.getGLEnum());
                this.magFilter = magFilter;
            }
        }
    }

    public void setFilter(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter) {
        this.minFilter = minFilter;
        this.magFilter = magFilter;
        bind();
        Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_MIN_FILTER, minFilter.getGLEnum());
        Gdx.gl.glTexParameteri(this.glTarget, GL20.GL_TEXTURE_MAG_FILTER, magFilter.getGLEnum());
    }

    public float unsafeSetAnisotropicFilter(float level) {
        return unsafeSetAnisotropicFilter(level, false);
    }

    public float unsafeSetAnisotropicFilter(float level, boolean force) {
        float max = getMaxAnisotropicFilterLevel();
        if (max == 1.0f) {
            return 1.0f;
        }
        float level2 = Math.min(level, max);
        if (!force && MathUtils.isEqual(level2, this.anisotropicFilterLevel, 0.1f)) {
            return this.anisotropicFilterLevel;
        }
        Gdx.gl20.glTexParameterf(GL20.GL_TEXTURE_2D, GL20.GL_TEXTURE_MAX_ANISOTROPY_EXT, level2);
        this.anisotropicFilterLevel = level2;
        return level2;
    }

    public float setAnisotropicFilter(float level) {
        float max = getMaxAnisotropicFilterLevel();
        if (max == 1.0f) {
            return 1.0f;
        }
        float level2 = Math.min(level, max);
        if (MathUtils.isEqual(level2, this.anisotropicFilterLevel, 0.1f)) {
            return level2;
        }
        bind();
        Gdx.gl20.glTexParameterf(GL20.GL_TEXTURE_2D, GL20.GL_TEXTURE_MAX_ANISOTROPY_EXT, level2);
        this.anisotropicFilterLevel = level2;
        return level2;
    }

    public float getAnisotropicFilter() {
        return this.anisotropicFilterLevel;
    }

    public static float getMaxAnisotropicFilterLevel() {
        float f = maxAnisotropicFilterLevel;
        if (f > 0.0f) {
            return f;
        }
        if (Gdx.graphics.supportsExtension("GL_EXT_texture_filter_anisotropic")) {
            FloatBuffer buffer = BufferUtils.newFloatBuffer(16);
            buffer.position(0);
            buffer.limit(buffer.capacity());
            Gdx.gl20.glGetFloatv(GL20.GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT, buffer);
            float f2 = buffer.get(0);
            maxAnisotropicFilterLevel = f2;
            return f2;
        }
        maxAnisotropicFilterLevel = 1.0f;
        return 1.0f;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void delete() {
        if (this.glHandle != 0) {
            Gdx.gl.glDeleteTexture(this.glHandle);
            this.glHandle = 0;
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        delete();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void uploadImageData(int target, TextureData data) {
        uploadImageData(target, data, 0);
    }

    public static void uploadImageData(int target, TextureData data, int miplevel) {
        Pixmap tmp;
        boolean disposePixmap;
        if (data == null) {
            return;
        }
        if (!data.isPrepared()) {
            data.prepare();
        }
        TextureData.TextureDataType type = data.getType();
        if (type == TextureData.TextureDataType.Custom) {
            data.consumeCustomData(target);
            return;
        }
        Pixmap pixmap = data.consumePixmap();
        boolean disposePixmap2 = data.disposePixmap();
        if (data.getFormat() == pixmap.getFormat()) {
            tmp = pixmap;
            disposePixmap = disposePixmap2;
        } else {
            tmp = new Pixmap(pixmap.getWidth(), pixmap.getHeight(), data.getFormat());
            tmp.setBlending(Pixmap.Blending.None);
            tmp.drawPixmap(pixmap, 0, 0, 0, 0, pixmap.getWidth(), pixmap.getHeight());
            if (data.disposePixmap()) {
                pixmap.dispose();
            }
            disposePixmap = true;
        }
        Gdx.gl.glPixelStorei(GL20.GL_UNPACK_ALIGNMENT, 1);
        if (data.useMipMaps()) {
            MipMapGenerator.generateMipMap(target, tmp, tmp.getWidth(), tmp.getHeight());
        } else {
            Gdx.gl.glTexImage2D(target, miplevel, tmp.getGLInternalFormat(), tmp.getWidth(), tmp.getHeight(), 0, tmp.getGLFormat(), tmp.getGLType(), tmp.getPixels());
        }
        if (disposePixmap) {
            tmp.dispose();
        }
    }
}