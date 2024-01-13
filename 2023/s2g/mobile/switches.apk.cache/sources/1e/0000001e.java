package com.badlogic.ashley.core;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.ReflectionPool;

/* loaded from: classes.dex */
public class PooledEngine extends Engine {
    private ComponentPools componentPools;
    private EntityPool entityPool;

    public PooledEngine() {
        this(10, 100, 10, 100);
    }

    public PooledEngine(int entityPoolInitialSize, int entityPoolMaxSize, int componentPoolInitialSize, int componentPoolMaxSize) {
        this.entityPool = new EntityPool(entityPoolInitialSize, entityPoolMaxSize);
        this.componentPools = new ComponentPools(componentPoolInitialSize, componentPoolMaxSize);
    }

    @Override // com.badlogic.ashley.core.Engine
    public Entity createEntity() {
        return this.entityPool.obtain();
    }

    @Override // com.badlogic.ashley.core.Engine
    public <T extends Component> T createComponent(Class<T> componentType) {
        return (T) this.componentPools.obtain(componentType);
    }

    public void clearPools() {
        this.entityPool.clear();
        this.componentPools.clear();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.ashley.core.Engine
    public void removeEntityInternal(Entity entity) {
        super.removeEntityInternal(entity);
        if (entity instanceof PooledEntity) {
            this.entityPool.free((PooledEntity) entity);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class PooledEntity extends Entity implements Pool.Poolable {
        private PooledEntity() {
        }

        @Override // com.badlogic.ashley.core.Entity
        public Component remove(Class<? extends Component> componentClass) {
            Component component = super.remove(componentClass);
            if (component != null) {
                PooledEngine.this.componentPools.free(component);
            }
            return component;
        }

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            removeAll();
            this.flags = 0;
            this.componentAdded.removeAllListeners();
            this.componentRemoved.removeAllListeners();
            this.scheduledForRemoval = false;
            this.removing = false;
        }
    }

    /* loaded from: classes.dex */
    private class EntityPool extends Pool<PooledEntity> {
        public EntityPool(int initialSize, int maxSize) {
            super(initialSize, maxSize);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public PooledEntity newObject() {
            return new PooledEntity();
        }
    }

    /* loaded from: classes.dex */
    private class ComponentPools {
        private int initialSize;
        private int maxSize;
        private ObjectMap<Class<?>, ReflectionPool> pools = new ObjectMap<>();

        public ComponentPools(int initialSize, int maxSize) {
            this.initialSize = initialSize;
            this.maxSize = maxSize;
        }

        public <T> T obtain(Class<T> type) {
            ReflectionPool pool = this.pools.get(type);
            if (pool == null) {
                pool = new ReflectionPool(type, this.initialSize, this.maxSize);
                this.pools.put(type, pool);
            }
            return pool.obtain();
        }

        public void free(Object object) {
            if (object == null) {
                throw new IllegalArgumentException("object cannot be null.");
            }
            ReflectionPool pool = this.pools.get(object.getClass());
            if (pool == null) {
                return;
            }
            pool.free(object);
        }

        public void freeAll(Array objects) {
            if (objects == null) {
                throw new IllegalArgumentException("objects cannot be null.");
            }
            int n = objects.size;
            for (int i = 0; i < n; i++) {
                Object object = objects.get(i);
                if (object != null) {
                    free(object);
                }
            }
        }

        public void clear() {
            ObjectMap.Values<ReflectionPool> it = this.pools.values().iterator();
            while (it.hasNext()) {
                Pool pool = it.next();
                pool.clear();
            }
        }
    }
}