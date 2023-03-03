package com.badlogic.gdx.graphics.glutils;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class MipMapGenerator {
    private static boolean useHWMipMap = true;

    private MipMapGenerator() {
    }

    public static void setUseHardwareMipMap(boolean useHWMipMap2) {
        useHWMipMap = useHWMipMap2;
    }

    public static void generateMipMap(Pixmap pixmap, int textureWidth, int textureHeight) {
        generateMipMap(GL20.GL_TEXTURE_2D, pixmap, textureWidth, textureHeight);
    }

    public static void generateMipMap(int target, Pixmap pixmap, int textureWidth, int textureHeight) {
        if (!useHWMipMap) {
            generateMipMapCPU(target, pixmap, textureWidth, textureHeight);
        } else if (Gdx.app.getType() == Application.ApplicationType.Android || Gdx.app.getType() == Application.ApplicationType.WebGL || Gdx.app.getType() == Application.ApplicationType.iOS) {
            generateMipMapGLES20(target, pixmap);
        } else {
            generateMipMapDesktop(target, pixmap, textureWidth, textureHeight);
        }
    }

    private static void generateMipMapGLES20(int target, Pixmap pixmap) {
        Gdx.gl.glTexImage2D(target, 0, pixmap.getGLInternalFormat(), pixmap.getWidth(), pixmap.getHeight(), 0, pixmap.getGLFormat(), pixmap.getGLType(), pixmap.getPixels());
        Gdx.gl20.glGenerateMipmap(target);
    }

    private static void generateMipMapDesktop(int target, Pixmap pixmap, int textureWidth, int textureHeight) {
        if (Gdx.graphics.supportsExtension("GL_ARB_framebuffer_object") || Gdx.graphics.supportsExtension("GL_EXT_framebuffer_object") || Gdx.gl30 != null) {
            Gdx.gl.glTexImage2D(target, 0, pixmap.getGLInternalFormat(), pixmap.getWidth(), pixmap.getHeight(), 0, pixmap.getGLFormat(), pixmap.getGLType(), pixmap.getPixels());
            Gdx.gl20.glGenerateMipmap(target);
            return;
        }
        generateMipMapCPU(target, pixmap, textureWidth, textureHeight);
    }

    private static void generateMipMapCPU(int target, Pixmap pixmap, int textureWidth, int textureHeight) {
        Gdx.gl.glTexImage2D(target, 0, pixmap.getGLInternalFormat(), pixmap.getWidth(), pixmap.getHeight(), 0, pixmap.getGLFormat(), pixmap.getGLType(), pixmap.getPixels());
        if (Gdx.gl20 == null && textureWidth != textureHeight) {
            throw new GdxRuntimeException("texture width and height must be square when using mipmapping.");
        }
        int width = pixmap.getWidth() / 2;
        int height = pixmap.getHeight() / 2;
        int level = 1;
        Pixmap pixmap2 = pixmap;
        while (width > 0 && height > 0) {
            Pixmap tmp = new Pixmap(width, height, pixmap2.getFormat());
            tmp.setBlending(Pixmap.Blending.None);
            tmp.drawPixmap(pixmap2, 0, 0, pixmap2.getWidth(), pixmap2.getHeight(), 0, 0, width, height);
            if (level > 1) {
                pixmap2.dispose();
            }
            pixmap2 = tmp;
            Gdx.gl.glTexImage2D(target, level, pixmap2.getGLInternalFormat(), pixmap2.getWidth(), pixmap2.getHeight(), 0, pixmap2.getGLFormat(), pixmap2.getGLType(), pixmap2.getPixels());
            width = pixmap2.getWidth() / 2;
            height = pixmap2.getHeight() / 2;
            level++;
        }
    }
}