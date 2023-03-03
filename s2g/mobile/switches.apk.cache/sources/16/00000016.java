package com.badlogic.ashley.core;

/* loaded from: classes.dex */
public abstract class EntitySystem {
    private Engine engine;
    public int priority;
    private boolean processing;

    public EntitySystem() {
        this(0);
    }

    public EntitySystem(int priority) {
        this.priority = priority;
        this.processing = true;
    }

    public void addedToEngine(Engine engine) {
    }

    public void removedFromEngine(Engine engine) {
    }

    public void update(float deltaTime) {
    }

    public boolean checkProcessing() {
        return this.processing;
    }

    public void setProcessing(boolean processing) {
        this.processing = processing;
    }

    public Engine getEngine() {
        return this.engine;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void addedToEngineInternal(Engine engine) {
        this.engine = engine;
        addedToEngine(engine);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void removedFromEngineInternal(Engine engine) {
        this.engine = null;
        removedFromEngine(engine);
    }
}