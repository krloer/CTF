package com.badlogic.ashley.core;

import com.badlogic.ashley.core.ComponentOperationHandler;
import com.badlogic.ashley.core.SystemManager;
import com.badlogic.ashley.signals.Listener;
import com.badlogic.ashley.signals.Signal;
import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.reflect.ClassReflection;
import com.badlogic.gdx.utils.reflect.ReflectionException;

/* loaded from: classes.dex */
public class Engine {
    private static Family empty = Family.all(new Class[0]).get();
    private boolean updating;
    private final Listener<Entity> componentAdded = new ComponentListener();
    private final Listener<Entity> componentRemoved = new ComponentListener();
    private SystemManager systemManager = new SystemManager(new EngineSystemListener());
    private EntityManager entityManager = new EntityManager(new EngineEntityListener());
    private ComponentOperationHandler componentOperationHandler = new ComponentOperationHandler(new EngineDelayedInformer());
    private FamilyManager familyManager = new FamilyManager(this.entityManager.getEntities());

    public Entity createEntity() {
        return new Entity();
    }

    public <T extends Component> T createComponent(Class<T> componentType) {
        try {
            return (T) ClassReflection.newInstance(componentType);
        } catch (ReflectionException e) {
            return null;
        }
    }

    public void addEntity(Entity entity) {
        boolean delayed = this.updating || this.familyManager.notifying();
        this.entityManager.addEntity(entity, delayed);
    }

    public void removeEntity(Entity entity) {
        boolean delayed = this.updating || this.familyManager.notifying();
        this.entityManager.removeEntity(entity, delayed);
    }

    public void removeAllEntities() {
        boolean delayed = this.updating || this.familyManager.notifying();
        this.entityManager.removeAllEntities(delayed);
    }

    public ImmutableArray<Entity> getEntities() {
        return this.entityManager.getEntities();
    }

    public void addSystem(EntitySystem system) {
        this.systemManager.addSystem(system);
    }

    public void removeSystem(EntitySystem system) {
        this.systemManager.removeSystem(system);
    }

    public <T extends EntitySystem> T getSystem(Class<T> systemType) {
        return (T) this.systemManager.getSystem(systemType);
    }

    public ImmutableArray<EntitySystem> getSystems() {
        return this.systemManager.getSystems();
    }

    public ImmutableArray<Entity> getEntitiesFor(Family family) {
        return this.familyManager.getEntitiesFor(family);
    }

    public void addEntityListener(EntityListener listener) {
        addEntityListener(empty, 0, listener);
    }

    public void addEntityListener(int priority, EntityListener listener) {
        addEntityListener(empty, priority, listener);
    }

    public void addEntityListener(Family family, EntityListener listener) {
        addEntityListener(family, 0, listener);
    }

    public void addEntityListener(Family family, int priority, EntityListener listener) {
        this.familyManager.addEntityListener(family, priority, listener);
    }

    public void removeEntityListener(EntityListener listener) {
        this.familyManager.removeEntityListener(listener);
    }

    public void update(float deltaTime) {
        if (this.updating) {
            throw new IllegalStateException("Cannot call update() on an Engine that is already updating.");
        }
        this.updating = true;
        ImmutableArray<EntitySystem> systems = this.systemManager.getSystems();
        for (int i = 0; i < systems.size(); i++) {
            try {
                EntitySystem system = systems.get(i);
                if (system.checkProcessing()) {
                    system.update(deltaTime);
                }
                this.componentOperationHandler.processOperations();
                this.entityManager.processPendingOperations();
            } finally {
                this.updating = false;
            }
        }
    }

    protected void addEntityInternal(Entity entity) {
        entity.componentAdded.add(this.componentAdded);
        entity.componentRemoved.add(this.componentRemoved);
        entity.componentOperationHandler = this.componentOperationHandler;
        this.familyManager.updateFamilyMembership(entity);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void removeEntityInternal(Entity entity) {
        this.familyManager.updateFamilyMembership(entity);
        entity.componentAdded.remove(this.componentAdded);
        entity.componentRemoved.remove(this.componentRemoved);
        entity.componentOperationHandler = null;
    }

    /* loaded from: classes.dex */
    private class ComponentListener implements Listener<Entity> {
        private ComponentListener() {
        }

        @Override // com.badlogic.ashley.signals.Listener
        public void receive(Signal<Entity> signal, Entity object) {
            Engine.this.familyManager.updateFamilyMembership(object);
        }
    }

    /* loaded from: classes.dex */
    private class EngineSystemListener implements SystemManager.SystemListener {
        private EngineSystemListener() {
        }

        @Override // com.badlogic.ashley.core.SystemManager.SystemListener
        public void systemAdded(EntitySystem system) {
            system.addedToEngineInternal(Engine.this);
        }

        @Override // com.badlogic.ashley.core.SystemManager.SystemListener
        public void systemRemoved(EntitySystem system) {
            system.removedFromEngineInternal(Engine.this);
        }
    }

    /* loaded from: classes.dex */
    private class EngineEntityListener implements EntityListener {
        private EngineEntityListener() {
        }

        @Override // com.badlogic.ashley.core.EntityListener
        public void entityAdded(Entity entity) {
            Engine.this.addEntityInternal(entity);
        }

        @Override // com.badlogic.ashley.core.EntityListener
        public void entityRemoved(Entity entity) {
            Engine.this.removeEntityInternal(entity);
        }
    }

    /* loaded from: classes.dex */
    private class EngineDelayedInformer implements ComponentOperationHandler.BooleanInformer {
        private EngineDelayedInformer() {
        }

        @Override // com.badlogic.ashley.core.ComponentOperationHandler.BooleanInformer
        public boolean value() {
            return Engine.this.updating;
        }
    }
}