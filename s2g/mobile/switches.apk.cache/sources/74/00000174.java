package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.environment.DirectionalLight;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class DirectionalLightsAttribute extends Attribute {
    public static final String Alias = "directionalLights";
    public static final long Type = register(Alias);
    public final Array<DirectionalLight> lights;

    public static final boolean is(long mask) {
        return (Type & mask) == mask;
    }

    public DirectionalLightsAttribute() {
        super(Type);
        this.lights = new Array<>(1);
    }

    public DirectionalLightsAttribute(DirectionalLightsAttribute copyFrom) {
        this();
        this.lights.addAll(copyFrom.lights);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public DirectionalLightsAttribute copy() {
        return new DirectionalLightsAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        Array.ArrayIterator<DirectionalLight> it = this.lights.iterator();
        while (it.hasNext()) {
            DirectionalLight light = it.next();
            result = (result * 1229) + (light == null ? 0 : light.hashCode());
        }
        return result;
    }

    @Override // java.lang.Comparable
    public int compareTo(Attribute o) {
        if (this.type != o.type) {
            return this.type < o.type ? -1 : 1;
        }
        return 0;
    }
}