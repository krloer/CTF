package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class ColorAttribute extends Attribute {
    public final Color color;
    public static final String DiffuseAlias = "diffuseColor";
    public static final long Diffuse = register(DiffuseAlias);
    public static final String SpecularAlias = "specularColor";
    public static final long Specular = register(SpecularAlias);
    public static final String AmbientAlias = "ambientColor";
    public static final long Ambient = register(AmbientAlias);
    public static final String EmissiveAlias = "emissiveColor";
    public static final long Emissive = register(EmissiveAlias);
    public static final String ReflectionAlias = "reflectionColor";
    public static final long Reflection = register(ReflectionAlias);
    public static final String AmbientLightAlias = "ambientLightColor";
    public static final long AmbientLight = register(AmbientLightAlias);
    public static final String FogAlias = "fogColor";
    public static final long Fog = register(FogAlias);
    protected static long Mask = (((((Ambient | Diffuse) | Specular) | Emissive) | Reflection) | AmbientLight) | Fog;

    public static final boolean is(long mask) {
        return (Mask & mask) != 0;
    }

    public static final ColorAttribute createAmbient(Color color) {
        return new ColorAttribute(Ambient, color);
    }

    public static final ColorAttribute createAmbient(float r, float g, float b, float a) {
        return new ColorAttribute(Ambient, r, g, b, a);
    }

    public static final ColorAttribute createDiffuse(Color color) {
        return new ColorAttribute(Diffuse, color);
    }

    public static final ColorAttribute createDiffuse(float r, float g, float b, float a) {
        return new ColorAttribute(Diffuse, r, g, b, a);
    }

    public static final ColorAttribute createSpecular(Color color) {
        return new ColorAttribute(Specular, color);
    }

    public static final ColorAttribute createSpecular(float r, float g, float b, float a) {
        return new ColorAttribute(Specular, r, g, b, a);
    }

    public static final ColorAttribute createReflection(Color color) {
        return new ColorAttribute(Reflection, color);
    }

    public static final ColorAttribute createReflection(float r, float g, float b, float a) {
        return new ColorAttribute(Reflection, r, g, b, a);
    }

    public static final ColorAttribute createEmissive(Color color) {
        return new ColorAttribute(Emissive, color);
    }

    public static final ColorAttribute createEmissive(float r, float g, float b, float a) {
        return new ColorAttribute(Emissive, r, g, b, a);
    }

    public static final ColorAttribute createAmbientLight(Color color) {
        return new ColorAttribute(AmbientLight, color);
    }

    public static final ColorAttribute createAmbientLight(float r, float g, float b, float a) {
        return new ColorAttribute(AmbientLight, r, g, b, a);
    }

    public static final ColorAttribute createFog(Color color) {
        return new ColorAttribute(Fog, color);
    }

    public static final ColorAttribute createFog(float r, float g, float b, float a) {
        return new ColorAttribute(Fog, r, g, b, a);
    }

    public ColorAttribute(long type) {
        super(type);
        this.color = new Color();
        if (!is(type)) {
            throw new GdxRuntimeException("Invalid type specified");
        }
    }

    public ColorAttribute(long type, Color color) {
        this(type);
        if (color != null) {
            this.color.set(color);
        }
    }

    public ColorAttribute(long type, float r, float g, float b, float a) {
        this(type);
        this.color.set(r, g, b, a);
    }

    public ColorAttribute(ColorAttribute copyFrom) {
        this(copyFrom.type, copyFrom.color);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public Attribute copy() {
        return new ColorAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        return (result * 953) + this.color.toIntBits();
    }

    @Override // java.lang.Comparable
    public int compareTo(Attribute o) {
        return this.type != o.type ? (int) (this.type - o.type) : ((ColorAttribute) o).color.toIntBits() - this.color.toIntBits();
    }
}