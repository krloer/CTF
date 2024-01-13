package com.badlogic.ashley.systems;

import com.badlogic.ashley.core.Engine;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.core.EntityListener;
import com.badlogic.ashley.core.EntitySystem;
import com.badlogic.ashley.core.Family;
import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.Array;
import java.util.Comparator;

/* loaded from: classes.dex */
public abstract class SortedIteratingSystem extends EntitySystem implements EntityListener {
    private Comparator<Entity> comparator;
    private final ImmutableArray<Entity> entities;
    private Family family;
    private boolean shouldSort;
    private Array<Entity> sortedEntities;

    protected abstract void processEntity(Entity entity, float f);

    public SortedIteratingSystem(Family family, Comparator<Entity> comparator) {
        this(family, comparator, 0);
    }

    public SortedIteratingSystem(Family family, Comparator<Entity> comparator, int priority) {
        super(priority);
        this.family = family;
        this.sortedEntities = new Array<>(false, 16);
        this.entities = new ImmutableArray<>(this.sortedEntities);
        this.comparator = comparator;
    }

    public void forceSort() {
        this.shouldSort = true;
    }

    private void sort() {
        if (this.shouldSort) {
            this.sortedEntities.sort(this.comparator);
            this.shouldSort = false;
        }
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void addedToEngine(Engine engine) {
        ImmutableArray<Entity> newEntities = engine.getEntitiesFor(this.family);
        this.sortedEntities.clear();
        if (newEntities.size() > 0) {
            for (int i = 0; i < newEntities.size(); i++) {
                this.sortedEntities.add(newEntities.get(i));
            }
            this.sortedEntities.sort(this.comparator);
        }
        this.shouldSort = false;
        engine.addEntityListener(this.family, this);
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void removedFromEngine(Engine engine) {
        engine.removeEntityListener(this);
        this.sortedEntities.clear();
        this.shouldSort = false;
    }

    @Override // com.badlogic.ashley.core.EntityListener
    public void entityAdded(Entity entity) {
        this.sortedEntities.add(entity);
        this.shouldSort = true;
    }

    @Override // com.badlogic.ashley.core.EntityListener
    public void entityRemoved(Entity entity) {
        this.sortedEntities.removeValue(entity, true);
        this.shouldSort = true;
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public void update(float deltaTime) {
        sort();
        for (int i = 0; i < this.sortedEntities.size; i++) {
            processEntity(this.sortedEntities.get(i), deltaTime);
        }
    }

    public ImmutableArray<Entity> getEntities() {
        sort();
        return this.entities;
    }

    public Family getFamily() {
        return this.family;
    }
}