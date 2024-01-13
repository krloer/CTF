package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL30;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureArrayData;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class FileTextureArrayData implements TextureArrayData {
    private int depth;
    private Pixmap.Format format;
    private boolean prepared;
    private TextureData[] textureDatas;
    boolean useMipMaps;

    public FileTextureArrayData(Pixmap.Format format, boolean useMipMaps, FileHandle[] files) {
        this.format = format;
        this.useMipMaps = useMipMaps;
        this.depth = files.length;
        this.textureDatas = new TextureData[files.length];
        for (int i = 0; i < files.length; i++) {
            this.textureDatas[i] = TextureData.Factory.loadFromFile(files[i], format, useMipMaps);
        }
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public boolean isPrepared() {
        return this.prepared;
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public void prepare() {
        TextureData[] textureDataArr;
        int width = -1;
        int height = -1;
        for (TextureData data : this.textureDatas) {
            data.prepare();
            if (width == -1) {
                width = data.getWidth();
                height = data.getHeight();
            } else if (width != data.getWidth() || height != data.getHeight()) {
                throw new GdxRuntimeException("Error whilst preparing TextureArray: TextureArray Textures must have equal dimensions.");
            }
        }
        this.prepared = true;
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public void consumeTextureArrayData() {
        Pixmap pixmap;
        boolean disposePixmap;
        int i = 0;
        while (true) {
            TextureData[] textureDataArr = this.textureDatas;
            if (i < textureDataArr.length) {
                if (textureDataArr[i].getType() == TextureData.TextureDataType.Custom) {
                    this.textureDatas[i].consumeCustomData(GL30.GL_TEXTURE_2D_ARRAY);
                } else {
                    TextureData texData = this.textureDatas[i];
                    Pixmap pixmap2 = texData.consumePixmap();
                    boolean disposePixmap2 = texData.disposePixmap();
                    if (texData.getFormat() == pixmap2.getFormat()) {
                        pixmap = pixmap2;
                        disposePixmap = disposePixmap2;
                    } else {
                        Pixmap temp = new Pixmap(pixmap2.getWidth(), pixmap2.getHeight(), texData.getFormat());
                        temp.setBlending(Pixmap.Blending.None);
                        temp.drawPixmap(pixmap2, 0, 0, 0, 0, pixmap2.getWidth(), pixmap2.getHeight());
                        if (texData.disposePixmap()) {
                            pixmap2.dispose();
                        }
                        pixmap = temp;
                        disposePixmap = true;
                    }
                    Gdx.gl30.glTexSubImage3D(GL30.GL_TEXTURE_2D_ARRAY, 0, 0, 0, i, pixmap.getWidth(), pixmap.getHeight(), 1, pixmap.getGLInternalFormat(), pixmap.getGLType(), pixmap.getPixels());
                    if (this.useMipMaps) {
                        Gdx.gl20.glGenerateMipmap(GL30.GL_TEXTURE_2D_ARRAY);
                    }
                    if (disposePixmap) {
                        pixmap.dispose();
                    }
                }
                i++;
            } else {
                return;
            }
        }
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public int getWidth() {
        return this.textureDatas[0].getWidth();
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public int getHeight() {
        return this.textureDatas[0].getHeight();
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public int getDepth() {
        return this.depth;
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public int getInternalFormat() {
        return Pixmap.Format.toGlFormat(this.format);
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public int getGLType() {
        return Pixmap.Format.toGlType(this.format);
    }

    @Override // com.badlogic.gdx.graphics.TextureArrayData
    public boolean isManaged() {
        TextureData[] textureDataArr;
        for (TextureData data : this.textureDatas) {
            if (!data.isManaged()) {
                return false;
            }
        }
        return true;
    }
}