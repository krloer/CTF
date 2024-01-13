package com.badlogic.ashley.core;

import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.Pool;
import java.util.Iterator;

/* loaded from: classes.dex */
class EntityManager {
    private EntityListener listener;
    private Array<Entity> entities = new Array<>(false, 16);
    private ObjectSet<Entity> entitySet = new ObjectSet<>();
    private ImmutableArray<Entity> immutableEntities = new ImmutableArray<>(this.entities);
    private Array<EntityOperation> pendingOperations = new Array<>(false, 16);
    private EntityOperationPool entityOperationPool = new EntityOperationPool(null);

    public EntityManager(EntityListener listener) {
        this.listener = listener;
    }

    public void addEntity(Entity entity) {
        addEntity(entity, false);
    }

    public void addEntity(Entity entity, boolean delayed) {
        if (delayed) {
            EntityOperation operation = this.entityOperationPool.obtain();
            operation.entity = entity;
            operation.type = EntityOperation.Type.Add;
            this.pendingOperations.add(operation);
            return;
        }
        addEntityInternal(entity);
    }

    public void removeEntity(Entity entity) {
        removeEntity(entity, false);
    }

    public void removeEntity(Entity entity, boolean delayed) {
        if (delayed) {
            if (entity.scheduledForRemoval) {
                return;
            }
            entity.scheduledForRemoval = true;
            EntityOperation operation = this.entityOperationPool.obtain();
            operation.entity = entity;
            operation.type = EntityOperation.Type.Remove;
            this.pendingOperations.add(operation);
            return;
        }
        removeEntityInternal(entity);
    }

    public void removeAllEntities() {
        removeAllEntities(false);
    }

    public void removeAllEntities(boolean delayed) {
        if (delayed) {
            Iterator it = this.entities.iterator();
            while (it.hasNext()) {
                Entity entity = (Entity) it.next();
                entity.scheduledForRemoval = true;
            }
            EntityOperation operation = this.entityOperationPool.obtain();
            operation.type = EntityOperation.Type.RemoveAll;
            this.pendingOperations.add(operation);
            return;
        }
        while (this.entities.size > 0) {
            removeEntity(this.entities.first(), false);
        }
    }

    public ImmutableArray<Entity> getEntities() {
        return this.immutableEntities;
    }

    public void processPendingOperations() {
        for (int i = 0; i < this.pendingOperations.size; i++) {
            EntityOperation operation = this.pendingOperations.get(i);
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$ashley$core$EntityManager$EntityOperation$Type[operation.type.ordinal()];
            if (i2 == 1) {
                addEntityInternal(operation.entity);
            } else if (i2 == 2) {
                removeEntityInternal(operation.entity);
            } else if (i2 == 3) {
                while (this.entities.size > 0) {
                    removeEntityInternal(this.entities.first());
                }
            } else {
                throw new AssertionError("Unexpected EntityOperation type");
            }
            this.entityOperationPool.free(operation);
        }
        this.pendingOperations.clear();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.ashley.core.EntityManager$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$ashley$core$EntityManager$EntityOperation$Type = new int[EntityOperation.Type.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$ashley$core$EntityManager$EntityOperation$Type[EntityOperation.Type.Add.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$ashley$core$EntityManager$EntityOperation$Type[EntityOperation.Type.Remove.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$ashley$core$EntityManager$EntityOperation$Type[EntityOperation.Type.RemoveAll.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }

    protected void removeEntityInternal(Entity entity) {
        boolean removed = this.entitySet.remove(entity);
        if (removed) {
            entity.scheduledForRemoval = false;
            entity.removing = true;
            this.entities.removeValue(entity, true);
            this.listener.entityRemoved(entity);
            entity.removing = false;
        }
    }

    protected void addEntityInternal(Entity entity) {
        if (this.entitySet.contains(entity)) {
            throw new IllegalArgumentException("Entity is already registered " + entity);
        }
        this.entities.add(entity);
        this.entitySet.add(entity);
        this.listener.entityAdded(entity);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class EntityOperation implements Pool.Poolable {
        public Entity entity;
        public Type type;

        /* loaded from: classes.dex */
        public enum Type {
            Add,
            Remove,
            RemoveAll
        }

        private EntityOperation() {
        }

        /* synthetic */ EntityOperation(AnonymousClass1 x0) {
            this();
        }

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.entity = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class EntityOperationPool extends Pool<EntityOperation> {
        private EntityOperationPool() {
        }

        /* synthetic */ EntityOperationPool(AnonymousClass1 x0) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public EntityOperation newObject() {
            return new EntityOperation(null);
        }
    }
}