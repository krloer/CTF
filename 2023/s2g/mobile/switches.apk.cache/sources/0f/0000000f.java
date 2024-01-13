package com.badlogic.ashley.core;

import com.badlogic.ashley.signals.Signal;
import com.badlogic.ashley.utils.Bag;
import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Bits;

/* loaded from: classes.dex */
public class Entity {
    ComponentOperationHandler componentOperationHandler;
    boolean removing;
    boolean scheduledForRemoval;
    private Bag<Component> components = new Bag<>();
    private Array<Component> componentsArray = new Array<>(false, 16);
    private ImmutableArray<Component> immutableComponentsArray = new ImmutableArray<>(this.componentsArray);
    private Bits componentBits = new Bits();
    private Bits familyBits = new Bits();
    public int flags = 0;
    public final Signal<Entity> componentAdded = new Signal<>();
    public final Signal<Entity> componentRemoved = new Signal<>();

    public Entity add(Component component) {
        if (addInternal(component)) {
            ComponentOperationHandler componentOperationHandler = this.componentOperationHandler;
            if (componentOperationHandler != null) {
                componentOperationHandler.add(this);
            } else {
                notifyComponentAdded();
            }
        }
        return this;
    }

    public Component addAndReturn(Component component) {
        add(component);
        return component;
    }

    public Component remove(Class<? extends Component> componentClass) {
        ComponentType componentType = ComponentType.getFor(componentClass);
        int componentTypeIndex = componentType.getIndex();
        Component removeComponent = this.components.get(componentTypeIndex);
        if (removeComponent != null && removeInternal(componentClass)) {
            ComponentOperationHandler componentOperationHandler = this.componentOperationHandler;
            if (componentOperationHandler != null) {
                componentOperationHandler.remove(this);
            } else {
                notifyComponentRemoved();
            }
        }
        return removeComponent;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void removeAll() {
        while (this.componentsArray.size > 0) {
            remove(this.componentsArray.get(0).getClass());
        }
    }

    public ImmutableArray<Component> getComponents() {
        return this.immutableComponentsArray;
    }

    public <T extends Component> T getComponent(Class<T> componentClass) {
        return (T) getComponent(ComponentType.getFor(componentClass));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public <T extends Component> T getComponent(ComponentType componentType) {
        int componentTypeIndex = componentType.getIndex();
        if (componentTypeIndex < this.components.getCapacity()) {
            return (T) this.components.get(componentType.getIndex());
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasComponent(ComponentType componentType) {
        return this.componentBits.get(componentType.getIndex());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Bits getComponentBits() {
        return this.componentBits;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Bits getFamilyBits() {
        return this.familyBits;
    }

    /* JADX WARN: Multi-variable type inference failed */
    boolean addInternal(Component component) {
        Class<?> cls = component.getClass();
        Component oldComponent = getComponent((Class<Component>) cls);
        if (component == oldComponent) {
            return false;
        }
        if (oldComponent != null) {
            removeInternal(cls);
        }
        int componentTypeIndex = ComponentType.getIndexFor(cls);
        this.components.set(componentTypeIndex, component);
        this.componentsArray.add(component);
        this.componentBits.set(componentTypeIndex);
        return true;
    }

    boolean removeInternal(Class<? extends Component> componentClass) {
        ComponentType componentType = ComponentType.getFor(componentClass);
        int componentTypeIndex = componentType.getIndex();
        Component removeComponent = this.components.get(componentTypeIndex);
        if (removeComponent != null) {
            this.components.set(componentTypeIndex, null);
            this.componentsArray.removeValue(removeComponent, true);
            this.componentBits.clear(componentTypeIndex);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void notifyComponentAdded() {
        this.componentAdded.dispatch(this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void notifyComponentRemoved() {
        this.componentRemoved.dispatch(this);
    }

    public boolean isScheduledForRemoval() {
        return this.scheduledForRemoval;
    }
}