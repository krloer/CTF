package com.badlogic.ashley.systems;

import com.badlogic.ashley.core.Engine;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.core.EntitySystem;
import com.badlogic.ashley.core.Family;
import com.badlogic.ashley.utils.ImmutableArray;

/* loaded from: classes.dex */
public abstract class IteratingSystem extends EntitySystem {
    private ImmutableArray<Entity> entities;
    private Family family;

    protected abstract void processEntity(Entity entity, float f);

    public IteratingSystem(Family family) {
        this(family, 0);
    }

    public IteratingSystem(Family family, int priority) {
        super(priority);
        this.family = family;
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void addedToEngine(Engine engine) {
        this.entities = engine.getEntitiesFor(this.family);
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void removedFromEngine(Engine engine) {
        this.entities = null;
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void update(float deltaTime) {
        for (int i = 0; i < this.entities.size(); i++) {
            processEntity(this.entities.get(i), deltaTime);
        }
    }

    public ImmutableArray<Entity> getEntities() {
        return this.entities;
    }

    public Family getFamily() {
        return this.family;
    }
}