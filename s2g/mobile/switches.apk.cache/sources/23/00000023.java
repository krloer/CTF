package com.badlogic.ashley.core;

import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import java.util.Comparator;

/* loaded from: classes.dex */
class SystemManager {
    private SystemListener listener;
    private SystemComparator systemComparator = new SystemComparator();
    private Array<EntitySystem> systems = new Array<>(true, 16);
    private ImmutableArray<EntitySystem> immutableSystems = new ImmutableArray<>(this.systems);
    private ObjectMap<Class<?>, EntitySystem> systemsByClass = new ObjectMap<>();

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface SystemListener {
        void systemAdded(EntitySystem entitySystem);

        void systemRemoved(EntitySystem entitySystem);
    }

    public SystemManager(SystemListener listener) {
        this.listener = listener;
    }

    public void addSystem(EntitySystem system) {
        Class<?> cls = system.getClass();
        EntitySystem oldSytem = getSystem(cls);
        if (oldSytem != null) {
            removeSystem(oldSytem);
        }
        this.systems.add(system);
        this.systemsByClass.put(cls, system);
        this.systems.sort(this.systemComparator);
        this.listener.systemAdded(system);
    }

    public void removeSystem(EntitySystem system) {
        if (this.systems.removeValue(system, true)) {
            this.systemsByClass.remove(system.getClass());
            this.listener.systemRemoved(system);
        }
    }

    public <T extends EntitySystem> T getSystem(Class<T> systemType) {
        return (T) this.systemsByClass.get(systemType);
    }

    public ImmutableArray<EntitySystem> getSystems() {
        return this.immutableSystems;
    }

    /* loaded from: classes.dex */
    private static class SystemComparator implements Comparator<EntitySystem> {
        private SystemComparator() {
        }

        @Override // java.util.Comparator
        public int compare(EntitySystem a, EntitySystem b) {
            if (a.priority > b.priority) {
                return 1;
            }
            return a.priority == b.priority ? 0 : -1;
        }
    }
}