package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.graphics.glutils.GLVersion;
import com.badlogic.gdx.utils.BufferUtils;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.nio.FloatBuffer;

/* loaded from: classes.dex */
public class FloatTextureData implements TextureData {
    FloatBuffer buffer;
    int format;
    int height;
    int internalFormat;
    boolean isGpuOnly;
    boolean isPrepared = false;
    int type;
    int width;

    public FloatTextureData(int w, int h, int internalFormat, int format, int type, boolean isGpuOnly) {
        this.width = 0;
        this.height = 0;
        this.width = w;
        this.height = h;
        this.internalFormat = internalFormat;
        this.format = format;
        this.type = type;
        this.isGpuOnly = isGpuOnly;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public TextureData.TextureDataType getType() {
        return TextureData.TextureDataType.Custom;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public boolean isPrepared() {
        return this.isPrepared;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public void prepare() {
        if (this.isPrepared) {
            throw new GdxRuntimeException("Already prepared");
        }
        if (!this.isGpuOnly) {
            int amountOfFloats = 4;
            if (Gdx.graphics.getGLVersion().getType().equals(GLVersion.Type.OpenGL)) {
                int i = this.internalFormat;
                amountOfFloats = (i == 34842 || i == 34836) ? 4 : 4;
                int i2 = this.internalFormat;
                amountOfFloats = (i2 == 34843 || i2 == 34837) ? 3 : 3;
                int i3 = this.internalFormat;
                amountOfFloats = (i3 == 33327 || i3 == 33328) ? 2 : 2;
                int i4 = this.internalFormat;
                if (i4 == 33325 || i4 == 33326) {
                    amountOfFloats = 1;
                }
            }
            this.buffer = BufferUtils.newFloatBuffer(this.width * this.height * amountOfFloats);
        }
        this.isPrepared = true;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public void consumeCustomData(int target) {
        if (Gdx.app.getType() == Application.ApplicationType.Android || Gdx.app.getType() == Application.ApplicationType.iOS || Gdx.app.getType() == Application.ApplicationType.WebGL) {
            if (!Gdx.graphics.supportsExtension("OES_texture_float")) {
                throw new GdxRuntimeException("Extension OES_texture_float not supported!");
            }
            Gdx.gl.glTexImage2D(target, 0, GL20.GL_RGBA, this.width, this.height, 0, GL20.GL_RGBA, GL20.GL_FLOAT, this.buffer);
        } else if (!Gdx.graphics.isGL30Available() && !Gdx.graphics.supportsExtension("GL_ARB_texture_float")) {
            throw new GdxRuntimeException("Extension GL_ARB_texture_float not supported!");
        } else {
            Gdx.gl.glTexImage2D(target, 0, this.internalFormat, this.width, this.height, 0, this.format, GL20.GL_FLOAT, this.buffer);
        }
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public Pixmap consumePixmap() {
        throw new GdxRuntimeException("This TextureData implementation does not return a Pixmap");
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public boolean disposePixmap() {
        throw new GdxRuntimeException("This TextureData implementation does not return a Pixmap");
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public int getWidth() {
        return this.width;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public int getHeight() {
        return this.height;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public Pixmap.Format getFormat() {
        return Pixmap.Format.RGBA8888;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public boolean useMipMaps() {
        return false;
    }

    @Override // com.badlogic.gdx.graphics.TextureData
    public boolean isManaged() {
        return true;
    }

    public FloatBuffer getBuffer() {
        return this.buffer;
    }
}