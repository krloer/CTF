package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Cubemap;
import com.badlogic.gdx.graphics.CubemapData;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.TextureData;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class FacedCubemapData implements CubemapData {
    protected final TextureData[] data;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public FacedCubemapData() {
        /*
            r8 = this;
            r0 = 0
            r7 = r0
            com.badlogic.gdx.graphics.TextureData r7 = (com.badlogic.gdx.graphics.TextureData) r7
            r1 = r8
            r2 = r7
            r3 = r7
            r4 = r7
            r5 = r7
            r6 = r7
            r1.<init>(r2, r3, r4, r5, r6, r7)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.glutils.FacedCubemapData.<init>():void");
    }

    public FacedCubemapData(FileHandle positiveX, FileHandle negativeX, FileHandle positiveY, FileHandle negativeY, FileHandle positiveZ, FileHandle negativeZ) {
        this(TextureData.Factory.loadFromFile(positiveX, false), TextureData.Factory.loadFromFile(negativeX, false), TextureData.Factory.loadFromFile(positiveY, false), TextureData.Factory.loadFromFile(negativeY, false), TextureData.Factory.loadFromFile(positiveZ, false), TextureData.Factory.loadFromFile(negativeZ, false));
    }

    public FacedCubemapData(FileHandle positiveX, FileHandle negativeX, FileHandle positiveY, FileHandle negativeY, FileHandle positiveZ, FileHandle negativeZ, boolean useMipMaps) {
        this(TextureData.Factory.loadFromFile(positiveX, useMipMaps), TextureData.Factory.loadFromFile(negativeX, useMipMaps), TextureData.Factory.loadFromFile(positiveY, useMipMaps), TextureData.Factory.loadFromFile(negativeY, useMipMaps), TextureData.Factory.loadFromFile(positiveZ, useMipMaps), TextureData.Factory.loadFromFile(negativeZ, useMipMaps));
    }

    public FacedCubemapData(Pixmap positiveX, Pixmap negativeX, Pixmap positiveY, Pixmap negativeY, Pixmap positiveZ, Pixmap negativeZ) {
        this(positiveX, negativeX, positiveY, negativeY, positiveZ, negativeZ, false);
    }

    public FacedCubemapData(Pixmap positiveX, Pixmap negativeX, Pixmap positiveY, Pixmap negativeY, Pixmap positiveZ, Pixmap negativeZ, boolean useMipMaps) {
        this(positiveX == null ? null : new PixmapTextureData(positiveX, null, useMipMaps, false), negativeX == null ? null : new PixmapTextureData(negativeX, null, useMipMaps, false), positiveY == null ? null : new PixmapTextureData(positiveY, null, useMipMaps, false), negativeY == null ? null : new PixmapTextureData(negativeY, null, useMipMaps, false), positiveZ == null ? null : new PixmapTextureData(positiveZ, null, useMipMaps, false), negativeZ == null ? null : new PixmapTextureData(negativeZ, null, useMipMaps, false));
    }

    public FacedCubemapData(int width, int height, int depth, Pixmap.Format format) {
        this(new PixmapTextureData(new Pixmap(depth, height, format), null, false, true), new PixmapTextureData(new Pixmap(depth, height, format), null, false, true), new PixmapTextureData(new Pixmap(width, depth, format), null, false, true), new PixmapTextureData(new Pixmap(width, depth, format), null, false, true), new PixmapTextureData(new Pixmap(width, height, format), null, false, true), new PixmapTextureData(new Pixmap(width, height, format), null, false, true));
    }

    public FacedCubemapData(TextureData positiveX, TextureData negativeX, TextureData positiveY, TextureData negativeY, TextureData positiveZ, TextureData negativeZ) {
        this.data = new TextureData[6];
        TextureData[] textureDataArr = this.data;
        textureDataArr[0] = positiveX;
        textureDataArr[1] = negativeX;
        textureDataArr[2] = positiveY;
        textureDataArr[3] = negativeY;
        textureDataArr[4] = positiveZ;
        textureDataArr[5] = negativeZ;
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public boolean isManaged() {
        TextureData[] textureDataArr;
        for (TextureData data : this.data) {
            if (!data.isManaged()) {
                return false;
            }
        }
        return true;
    }

    public void load(Cubemap.CubemapSide side, FileHandle file) {
        this.data[side.index] = TextureData.Factory.loadFromFile(file, false);
    }

    public void load(Cubemap.CubemapSide side, Pixmap pixmap) {
        this.data[side.index] = pixmap != null ? new PixmapTextureData(pixmap, null, false, false) : null;
    }

    public boolean isComplete() {
        int i = 0;
        while (true) {
            TextureData[] textureDataArr = this.data;
            if (i < textureDataArr.length) {
                if (textureDataArr[i] == null) {
                    return false;
                }
                i++;
            } else {
                return true;
            }
        }
    }

    public TextureData getTextureData(Cubemap.CubemapSide side) {
        return this.data[side.index];
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public int getWidth() {
        int tmp;
        int tmp2;
        int tmp3;
        int tmp4;
        int width = 0;
        if (this.data[Cubemap.CubemapSide.PositiveZ.index] != null && (tmp4 = this.data[Cubemap.CubemapSide.PositiveZ.index].getWidth()) > 0) {
            width = tmp4;
        }
        if (this.data[Cubemap.CubemapSide.NegativeZ.index] != null && (tmp3 = this.data[Cubemap.CubemapSide.NegativeZ.index].getWidth()) > width) {
            width = tmp3;
        }
        if (this.data[Cubemap.CubemapSide.PositiveY.index] != null && (tmp2 = this.data[Cubemap.CubemapSide.PositiveY.index].getWidth()) > width) {
            width = tmp2;
        }
        return (this.data[Cubemap.CubemapSide.NegativeY.index] == null || (tmp = this.data[Cubemap.CubemapSide.NegativeY.index].getWidth()) <= width) ? width : tmp;
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public int getHeight() {
        int tmp;
        int tmp2;
        int tmp3;
        int tmp4;
        int height = 0;
        if (this.data[Cubemap.CubemapSide.PositiveZ.index] != null && (tmp4 = this.data[Cubemap.CubemapSide.PositiveZ.index].getHeight()) > 0) {
            height = tmp4;
        }
        if (this.data[Cubemap.CubemapSide.NegativeZ.index] != null && (tmp3 = this.data[Cubemap.CubemapSide.NegativeZ.index].getHeight()) > height) {
            height = tmp3;
        }
        if (this.data[Cubemap.CubemapSide.PositiveX.index] != null && (tmp2 = this.data[Cubemap.CubemapSide.PositiveX.index].getHeight()) > height) {
            height = tmp2;
        }
        if (this.data[Cubemap.CubemapSide.NegativeX.index] != null && (tmp = this.data[Cubemap.CubemapSide.NegativeX.index].getHeight()) > height) {
            return tmp;
        }
        return height;
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public boolean isPrepared() {
        return false;
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public void prepare() {
        if (!isComplete()) {
            throw new GdxRuntimeException("You need to complete your cubemap data before using it");
        }
        int i = 0;
        while (true) {
            TextureData[] textureDataArr = this.data;
            if (i < textureDataArr.length) {
                if (!textureDataArr[i].isPrepared()) {
                    this.data[i].prepare();
                }
                i++;
            } else {
                return;
            }
        }
    }

    @Override // com.badlogic.gdx.graphics.CubemapData
    public void consumeCubemapData() {
        int i = 0;
        while (true) {
            TextureData[] textureDataArr = this.data;
            if (i < textureDataArr.length) {
                if (textureDataArr[i].getType() == TextureData.TextureDataType.Custom) {
                    this.data[i].consumeCustomData(GL20.GL_TEXTURE_CUBE_MAP_POSITIVE_X + i);
                } else {
                    Pixmap pixmap = this.data[i].consumePixmap();
                    boolean disposePixmap = this.data[i].disposePixmap();
                    if (this.data[i].getFormat() != pixmap.getFormat()) {
                        Pixmap tmp = new Pixmap(pixmap.getWidth(), pixmap.getHeight(), this.data[i].getFormat());
                        tmp.setBlending(Pixmap.Blending.None);
                        tmp.drawPixmap(pixmap, 0, 0, 0, 0, pixmap.getWidth(), pixmap.getHeight());
                        if (this.data[i].disposePixmap()) {
                            pixmap.dispose();
                        }
                        pixmap = tmp;
                        disposePixmap = true;
                    }
                    Gdx.gl.glPixelStorei(GL20.GL_UNPACK_ALIGNMENT, 1);
                    Gdx.gl.glTexImage2D(i + GL20.GL_TEXTURE_CUBE_MAP_POSITIVE_X, 0, pixmap.getGLInternalFormat(), pixmap.getWidth(), pixmap.getHeight(), 0, pixmap.getGLFormat(), pixmap.getGLType(), pixmap.getPixels());
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
}