package com.badlogic.gdx.graphics.g3d;

import com.badlogic.gdx.utils.Array;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Material extends Attributes {
    private static int counter = 0;
    public String id;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public Material() {
        /*
            r2 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "mtl"
            r0.append(r1)
            int r1 = com.badlogic.gdx.graphics.g3d.Material.counter
            int r1 = r1 + 1
            com.badlogic.gdx.graphics.g3d.Material.counter = r1
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r2.<init>(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.g3d.Material.<init>():void");
    }

    public Material(String id) {
        this.id = id;
    }

    public Material(Attribute... attributes) {
        this();
        set(attributes);
    }

    public Material(String id, Attribute... attributes) {
        this(id);
        set(attributes);
    }

    public Material(Array<Attribute> attributes) {
        this();
        set(attributes);
    }

    public Material(String id, Array<Attribute> attributes) {
        this(id);
        set(attributes);
    }

    public Material(Material copyFrom) {
        this(copyFrom.id, copyFrom);
    }

    public Material(String id, Material copyFrom) {
        this(id);
        Iterator<Attribute> it = copyFrom.iterator();
        while (it.hasNext()) {
            Attribute attr = it.next();
            set(attr.copy());
        }
    }

    public Material copy() {
        return new Material(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attributes
    public int hashCode() {
        return super.hashCode() + (this.id.hashCode() * 3);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attributes, java.util.Comparator
    public boolean equals(Object other) {
        return (other instanceof Material) && (other == this || (((Material) other).id.equals(this.id) && super.equals(other)));
    }
}