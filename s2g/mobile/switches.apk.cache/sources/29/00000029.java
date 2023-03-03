package com.badlogic.ashley.systems;

import com.badlogic.ashley.core.Engine;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.core.Family;
import com.badlogic.ashley.utils.ImmutableArray;

/* loaded from: classes.dex */
public abstract class IntervalIteratingSystem extends IntervalSystem {
    private ImmutableArray<Entity> entities;
    private Family family;

    protected abstract void processEntity(Entity entity);

    public IntervalIteratingSystem(Family family, float interval) {
        this(family, interval, 0);
    }

    public IntervalIteratingSystem(Family family, float interval, int priority) {
        super(interval, priority);
        this.family = family;
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void addedToEngine(Engine engine) {
        this.entities = engine.getEntitiesFor(this.family);
    }

    @Override // com.badlogic.ashley.systems.IntervalSystem
    protected void updateInterval() {
        for (int i = 0; i < this.entities.size(); i++) {
            processEntity(this.entities.get(i));
        }
    }

    public ImmutableArray<Entity> getEntities() {
        return this.entities;
    }

    public Family getFamily() {
        return this.family;
    }
}