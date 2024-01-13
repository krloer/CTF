package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.GLTexture;
import com.badlogic.gdx.graphics.Texture;

/* loaded from: classes.dex */
public class TextureDescriptor<T extends GLTexture> implements Comparable<TextureDescriptor<T>> {
    public Texture.TextureFilter magFilter;
    public Texture.TextureFilter minFilter;
    public T texture;
    public Texture.TextureWrap uWrap;
    public Texture.TextureWrap vWrap;

    @Override // java.lang.Comparable
    public /* bridge */ /* synthetic */ int compareTo(Object obj) {
        return compareTo((TextureDescriptor) ((TextureDescriptor) obj));
    }

    public TextureDescriptor(T texture, Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, Texture.TextureWrap uWrap, Texture.TextureWrap vWrap) {
        this.texture = null;
        set(texture, minFilter, magFilter, uWrap, vWrap);
    }

    public TextureDescriptor(T texture) {
        this(texture, null, null, null, null);
    }

    public TextureDescriptor() {
        this.texture = null;
    }

    public void set(T texture, Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, Texture.TextureWrap uWrap, Texture.TextureWrap vWrap) {
        this.texture = texture;
        this.minFilter = minFilter;
        this.magFilter = magFilter;
        this.uWrap = uWrap;
        this.vWrap = vWrap;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [T extends com.badlogic.gdx.graphics.GLTexture] */
    public <V extends T> void set(TextureDescriptor<V> other) {
        this.texture = other.texture;
        this.minFilter = other.minFilter;
        this.magFilter = other.magFilter;
        this.uWrap = other.uWrap;
        this.vWrap = other.vWrap;
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof TextureDescriptor)) {
            return false;
        }
        TextureDescriptor<?> other = (TextureDescriptor) obj;
        return other.texture == this.texture && other.minFilter == this.minFilter && other.magFilter == this.magFilter && other.uWrap == this.uWrap && other.vWrap == this.vWrap;
    }

    public int hashCode() {
        T t;
        Texture.TextureFilter textureFilter;
        Texture.TextureFilter textureFilter2;
        Texture.TextureWrap textureWrap;
        Texture.TextureWrap textureWrap2;
        T t2 = this.texture;
        long result = t2 == null ? 0 : t2.glTarget;
        long result2 = (811 * ((((((((result * 811) + (this.texture == null ? 0 : t.getTextureObjectHandle())) * 811) + (this.minFilter == null ? 0 : textureFilter.getGLEnum())) * 811) + (this.magFilter == null ? 0 : textureFilter2.getGLEnum())) * 811) + (this.uWrap == null ? 0 : textureWrap.getGLEnum()))) + (this.vWrap != null ? textureWrap2.getGLEnum() : 0);
        return (int) ((result2 >> 32) ^ result2);
    }

    public int compareTo(TextureDescriptor<T> o) {
        if (o == this) {
            return 0;
        }
        T t = this.texture;
        int t1 = t == null ? 0 : t.glTarget;
        T t2 = o.texture;
        int t22 = t2 == null ? 0 : t2.glTarget;
        if (t1 != t22) {
            return t1 - t22;
        }
        T t3 = this.texture;
        int h1 = t3 == null ? 0 : t3.getTextureObjectHandle();
        T t4 = o.texture;
        int h2 = t4 == null ? 0 : t4.getTextureObjectHandle();
        if (h1 != h2) {
            return h1 - h2;
        }
        Texture.TextureFilter textureFilter = this.minFilter;
        if (textureFilter != o.minFilter) {
            int gLEnum = textureFilter == null ? 0 : textureFilter.getGLEnum();
            Texture.TextureFilter textureFilter2 = o.minFilter;
            return gLEnum - (textureFilter2 != null ? textureFilter2.getGLEnum() : 0);
        }
        Texture.TextureFilter textureFilter3 = this.magFilter;
        if (textureFilter3 != o.magFilter) {
            int gLEnum2 = textureFilter3 == null ? 0 : textureFilter3.getGLEnum();
            Texture.TextureFilter textureFilter4 = o.magFilter;
            return gLEnum2 - (textureFilter4 != null ? textureFilter4.getGLEnum() : 0);
        }
        Texture.TextureWrap textureWrap = this.uWrap;
        if (textureWrap != o.uWrap) {
            int gLEnum3 = textureWrap == null ? 0 : textureWrap.getGLEnum();
            Texture.TextureWrap textureWrap2 = o.uWrap;
            return gLEnum3 - (textureWrap2 != null ? textureWrap2.getGLEnum() : 0);
        }
        Texture.TextureWrap textureWrap3 = this.vWrap;
        if (textureWrap3 != o.vWrap) {
            int gLEnum4 = textureWrap3 == null ? 0 : textureWrap3.getGLEnum();
            Texture.TextureWrap textureWrap4 = o.vWrap;
            return gLEnum4 - (textureWrap4 != null ? textureWrap4.getGLEnum() : 0);
        }
        return 0;
    }
}