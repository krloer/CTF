package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.g3d.Attribute;

/* loaded from: classes.dex */
public class IntAttribute extends Attribute {
    public int value;
    public static final String CullFaceAlias = "cullface";
    public static final long CullFace = register(CullFaceAlias);

    public static IntAttribute createCullFace(int value) {
        return new IntAttribute(CullFace, value);
    }

    public IntAttribute(long type) {
        super(type);
    }

    public IntAttribute(long type, int value) {
        super(type);
        this.value = value;
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public Attribute copy() {
        return new IntAttribute(this.type, this.value);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        return (result * 983) + this.value;
    }

    @Override // java.lang.Comparable
    public int compareTo(Attribute o) {
        return this.type != o.type ? (int) (this.type - o.type) : this.value - ((IntAttribute) o).value;
    }
}