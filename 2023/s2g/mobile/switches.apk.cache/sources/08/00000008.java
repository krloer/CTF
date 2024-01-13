package com.badlogic.ashley.core;

import com.badlogic.gdx.utils.Bits;
import com.badlogic.gdx.utils.ObjectMap;

/* loaded from: classes.dex */
public final class ComponentType {
    private static ObjectMap<Class<? extends Component>, ComponentType> assignedComponentTypes = new ObjectMap<>();
    private static int typeIndex = 0;
    private final int index;

    private ComponentType() {
        int i = typeIndex;
        typeIndex = i + 1;
        this.index = i;
    }

    public int getIndex() {
        return this.index;
    }

    public static ComponentType getFor(Class<? extends Component> componentType) {
        ComponentType type = assignedComponentTypes.get(componentType);
        if (type == null) {
            ComponentType type2 = new ComponentType();
            assignedComponentTypes.put(componentType, type2);
            return type2;
        }
        return type;
    }

    public static int getIndexFor(Class<? extends Component> componentType) {
        return getFor(componentType).getIndex();
    }

    public static Bits getBitsFor(Class<? extends Component>... componentTypes) {
        Bits bits = new Bits();
        for (Class<? extends Component> cls : componentTypes) {
            bits.set(getIndexFor(cls));
        }
        return bits;
    }

    public int hashCode() {
        return this.index;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        ComponentType other = (ComponentType) obj;
        return this.index == other.index;
    }
}