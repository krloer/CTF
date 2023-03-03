package com.badlogic.gdx.graphics.g3d.attributes;

import com.badlogic.gdx.graphics.g3d.Attribute;
import com.badlogic.gdx.graphics.g3d.environment.PointLight;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class PointLightsAttribute extends Attribute {
    public static final String Alias = "pointLights";
    public static final long Type = register(Alias);
    public final Array<PointLight> lights;

    public static final boolean is(long mask) {
        return (Type & mask) == mask;
    }

    public PointLightsAttribute() {
        super(Type);
        this.lights = new Array<>(1);
    }

    public PointLightsAttribute(PointLightsAttribute copyFrom) {
        this();
        this.lights.addAll(copyFrom.lights);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public PointLightsAttribute copy() {
        return new PointLightsAttribute(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.Attribute
    public int hashCode() {
        int result = super.hashCode();
        Array.ArrayIterator<PointLight> it = this.lights.iterator();
        while (it.hasNext()) {
            PointLight light = it.next();
            result = (result * 1231) + (light == null ? 0 : light.hashCode());
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