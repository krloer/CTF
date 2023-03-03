package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.environment.SpotLight;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class SpotLightsAttribute extends Attribute {
    public static final String Alias = "spotLights";
    public static final long Type = register(Alias);
    public final Array<SpotLight> lights;

    public static final boolean is(long mask) {
        return (Type & mask) == mask;
    }

    public SpotLightsAttribute() {
        super(Type);
        this.lights = new Array<>(1);
    }

    public SpotLightsAttribute(SpotLightsAttribute copyFrom) {
        this();
        this.lights.addAll(copyFrom.lights);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public SpotLightsAttribute copy() {
        return new SpotLightsAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        Array.ArrayIterator<SpotLight> it = this.lights.iterator();
        while (it.hasNext()) {
            SpotLight light = it.next();
            result = (result * 1237) + (light == null ? 0 : light.hashCode());
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