package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.Cubemap;
import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.utils.TextureDescriptor;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class CubemapAttribute extends Attribute {
    public final TextureDescriptor<Cubemap> textureDescription;
    public static final String EnvironmentMapAlias = "environmentCubemap";
    public static final long EnvironmentMap = register(EnvironmentMapAlias);
    protected static long Mask = EnvironmentMap;

    public static final boolean is(long mask) {
        return (Mask & mask) != 0;
    }

    public CubemapAttribute(long type) {
        super(type);
        if (!is(type)) {
            throw new GdxRuntimeException("Invalid type specified");
        }
        this.textureDescription = new TextureDescriptor<>();
    }

    public <T extends Cubemap> CubemapAttribute(long type, TextureDescriptor<T> textureDescription) {
        this(type);
        this.textureDescription.set(textureDescription);
    }

    public CubemapAttribute(long type, Cubemap texture) {
        this(type);
        this.textureDescription.texture = texture;
    }

    public CubemapAttribute(CubemapAttribute copyFrom) {
        this(copyFrom.type, copyFrom.textureDescription);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public Attribute copy() {
        return new CubemapAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        return (result * 967) + this.textureDescription.hashCode();
    }

    @Override // java.lang.Comparable
    public int compareTo(Attribute o) {
        return this.type != o.type ? (int) (this.type - o.type) : this.textureDescription.compareTo(((CubemapAttribute) o).textureDescription);
    }
}