package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.utils.TextureDescriptor;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.NumberUtils;

/* loaded from: classes.dex */
public class TextureAttribute extends Attribute {
    public float offsetU;
    public float offsetV;
    public float scaleU;
    public float scaleV;
    public final TextureDescriptor<Texture> textureDescription;
    public int uvIndex;
    public static final String DiffuseAlias = "diffuseTexture";
    public static final long Diffuse = register(DiffuseAlias);
    public static final String SpecularAlias = "specularTexture";
    public static final long Specular = register(SpecularAlias);
    public static final String BumpAlias = "bumpTexture";
    public static final long Bump = register(BumpAlias);
    public static final String NormalAlias = "normalTexture";
    public static final long Normal = register(NormalAlias);
    public static final String AmbientAlias = "ambientTexture";
    public static final long Ambient = register(AmbientAlias);
    public static final String EmissiveAlias = "emissiveTexture";
    public static final long Emissive = register(EmissiveAlias);
    public static final String ReflectionAlias = "reflectionTexture";
    public static final long Reflection = register(ReflectionAlias);
    protected static long Mask = (((((Diffuse | Specular) | Bump) | Normal) | Ambient) | Emissive) | Reflection;

    public static final boolean is(long mask) {
        return (Mask & mask) != 0;
    }

    public static TextureAttribute createDiffuse(Texture texture) {
        return new TextureAttribute(Diffuse, texture);
    }

    public static TextureAttribute createDiffuse(TextureRegion region) {
        return new TextureAttribute(Diffuse, region);
    }

    public static TextureAttribute createSpecular(Texture texture) {
        return new TextureAttribute(Specular, texture);
    }

    public static TextureAttribute createSpecular(TextureRegion region) {
        return new TextureAttribute(Specular, region);
    }

    public static TextureAttribute createNormal(Texture texture) {
        return new TextureAttribute(Normal, texture);
    }

    public static TextureAttribute createNormal(TextureRegion region) {
        return new TextureAttribute(Normal, region);
    }

    public static TextureAttribute createBump(Texture texture) {
        return new TextureAttribute(Bump, texture);
    }

    public static TextureAttribute createBump(TextureRegion region) {
        return new TextureAttribute(Bump, region);
    }

    public static TextureAttribute createAmbient(Texture texture) {
        return new TextureAttribute(Ambient, texture);
    }

    public static TextureAttribute createAmbient(TextureRegion region) {
        return new TextureAttribute(Ambient, region);
    }

    public static TextureAttribute createEmissive(Texture texture) {
        return new TextureAttribute(Emissive, texture);
    }

    public static TextureAttribute createEmissive(TextureRegion region) {
        return new TextureAttribute(Emissive, region);
    }

    public static TextureAttribute createReflection(Texture texture) {
        return new TextureAttribute(Reflection, texture);
    }

    public static TextureAttribute createReflection(TextureRegion region) {
        return new TextureAttribute(Reflection, region);
    }

    public TextureAttribute(long type) {
        super(type);
        this.offsetU = 0.0f;
        this.offsetV = 0.0f;
        this.scaleU = 1.0f;
        this.scaleV = 1.0f;
        this.uvIndex = 0;
        if (!is(type)) {
            throw new GdxRuntimeException("Invalid type specified");
        }
        this.textureDescription = new TextureDescriptor<>();
    }

    public <T extends Texture> TextureAttribute(long type, TextureDescriptor<T> textureDescription) {
        this(type);
        this.textureDescription.set(textureDescription);
    }

    public <T extends Texture> TextureAttribute(long type, TextureDescriptor<T> textureDescription, float offsetU, float offsetV, float scaleU, float scaleV, int uvIndex) {
        this(type, textureDescription);
        this.offsetU = offsetU;
        this.offsetV = offsetV;
        this.scaleU = scaleU;
        this.scaleV = scaleV;
        this.uvIndex = uvIndex;
    }

    public <T extends Texture> TextureAttribute(long type, TextureDescriptor<T> textureDescription, float offsetU, float offsetV, float scaleU, float scaleV) {
        this(type, textureDescription, offsetU, offsetV, scaleU, scaleV, 0);
    }

    public TextureAttribute(long type, Texture texture) {
        this(type);
        this.textureDescription.texture = texture;
    }

    public TextureAttribute(long type, TextureRegion region) {
        this(type);
        set(region);
    }

    public TextureAttribute(TextureAttribute copyFrom) {
        this(copyFrom.type, copyFrom.textureDescription, copyFrom.offsetU, copyFrom.offsetV, copyFrom.scaleU, copyFrom.scaleV, copyFrom.uvIndex);
    }

    public void set(TextureRegion region) {
        this.textureDescription.texture = region.getTexture();
        this.offsetU = region.getU();
        this.offsetV = region.getV();
        this.scaleU = region.getU2() - this.offsetU;
        this.scaleV = region.getV2() - this.offsetV;
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public Attribute copy() {
        return new TextureAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        return (((((((((((result * 991) + this.textureDescription.hashCode()) * 991) + NumberUtils.floatToRawIntBits(this.offsetU)) * 991) + NumberUtils.floatToRawIntBits(this.offsetV)) * 991) + NumberUtils.floatToRawIntBits(this.scaleU)) * 991) + NumberUtils.floatToRawIntBits(this.scaleV)) * 991) + this.uvIndex;
    }

    @Override // java.lang.Comparable
    public int compareTo(Attribute o) {
        if (this.type != o.type) {
            return this.type < o.type ? -1 : 1;
        }
        TextureAttribute other = (TextureAttribute) o;
        int c = this.textureDescription.compareTo(other.textureDescription);
        if (c != 0) {
            return c;
        }
        int i = this.uvIndex;
        int i2 = other.uvIndex;
        if (i != i2) {
            return i - i2;
        }
        if (!MathUtils.isEqual(this.scaleU, other.scaleU)) {
            return this.scaleU > other.scaleU ? 1 : -1;
        } else if (!MathUtils.isEqual(this.scaleV, other.scaleV)) {
            return this.scaleV > other.scaleV ? 1 : -1;
        } else if (!MathUtils.isEqual(this.offsetU, other.offsetU)) {
            return this.offsetU > other.offsetU ? 1 : -1;
        } else if (MathUtils.isEqual(this.offsetV, other.offsetV)) {
            return 0;
        } else {
            return this.offsetV > other.offsetV ? 1 : -1;
        }
    }
}