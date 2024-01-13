package com.badlogic.ashley.core;

import com.badlogic.ashley.core.Component;

/* loaded from: classes.dex */
public final class ComponentMapper<T extends Component> {
    private final ComponentType componentType;

    public static <T extends Component> ComponentMapper<T> getFor(Class<T> componentClass) {
        return new ComponentMapper<>(componentClass);
    }

    public T get(Entity entity) {
        return (T) entity.getComponent(this.componentType);
    }

    public boolean has(Entity entity) {
        return entity.hasComponent(this.componentType);
    }

    private ComponentMapper(Class<T> componentClass) {
        this.componentType = ComponentType.getFor(componentClass);
    }
}