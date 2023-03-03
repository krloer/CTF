package com.badlogic.ashley.core;

import com.badlogic.ashley.utils.ImmutableArray;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Bits;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.SnapshotArray;
import java.util.Iterator;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FamilyManager {
    ImmutableArray<Entity> entities;
    private ObjectMap<Family, Array<Entity>> families = new ObjectMap<>();
    private ObjectMap<Family, ImmutableArray<Entity>> immutableFamilies = new ObjectMap<>();
    private SnapshotArray<EntityListenerData> entityListeners = new SnapshotArray<>(true, 16);
    private ObjectMap<Family, Bits> entityListenerMasks = new ObjectMap<>();
    private BitsPool bitsPool = new BitsPool();
    private boolean notifying = false;

    public FamilyManager(ImmutableArray<Entity> entities) {
        this.entities = entities;
    }

    public ImmutableArray<Entity> getEntitiesFor(Family family) {
        return registerFamily(family);
    }

    public boolean notifying() {
        return this.notifying;
    }

    public void addEntityListener(Family family, int priority, EntityListener listener) {
        registerFamily(family);
        int insertionIndex = 0;
        while (insertionIndex < this.entityListeners.size && this.entityListeners.get(insertionIndex).priority <= priority) {
            insertionIndex++;
        }
        ObjectMap.Values<Bits> it = this.entityListenerMasks.values().iterator();
        while (it.hasNext()) {
            Bits mask = it.next();
            for (int k = mask.length(); k > insertionIndex; k--) {
                if (mask.get(k - 1)) {
                    mask.set(k);
                } else {
                    mask.clear(k);
                }
            }
            mask.clear(insertionIndex);
        }
        this.entityListenerMasks.get(family).set(insertionIndex);
        EntityListenerData entityListenerData = new EntityListenerData();
        entityListenerData.listener = listener;
        entityListenerData.priority = priority;
        this.entityListeners.insert(insertionIndex, entityListenerData);
    }

    public void removeEntityListener(EntityListener listener) {
        int i = 0;
        while (i < this.entityListeners.size) {
            EntityListenerData entityListenerData = this.entityListeners.get(i);
            if (entityListenerData.listener == listener) {
                ObjectMap.Values<Bits> it = this.entityListenerMasks.values().iterator();
                while (it.hasNext()) {
                    Bits mask = it.next();
                    int n = mask.length();
                    for (int k = i; k < n; k++) {
                        if (mask.get(k + 1)) {
                            mask.set(k);
                        } else {
                            mask.clear(k);
                        }
                    }
                }
                this.entityListeners.removeIndex(i);
                i--;
            }
            i++;
        }
    }

    public void updateFamilyMembership(Entity entity) {
        Bits addListenerBits = this.bitsPool.obtain();
        Bits removeListenerBits = this.bitsPool.obtain();
        ObjectMap.Keys<Family> it = this.entityListenerMasks.keys().iterator();
        while (true) {
            boolean matches = false;
            if (!it.hasNext()) {
                break;
            }
            Family family = it.next();
            int familyIndex = family.getIndex();
            Bits entityFamilyBits = entity.getFamilyBits();
            boolean belongsToFamily = entityFamilyBits.get(familyIndex);
            if (family.matches(entity) && !entity.removing) {
                matches = true;
            }
            if (belongsToFamily != matches) {
                Bits listenersMask = this.entityListenerMasks.get(family);
                Array<Entity> familyEntities = this.families.get(family);
                if (matches) {
                    addListenerBits.or(listenersMask);
                    familyEntities.add(entity);
                    entityFamilyBits.set(familyIndex);
                } else {
                    removeListenerBits.or(listenersMask);
                    familyEntities.removeValue(entity, true);
                    entityFamilyBits.clear(familyIndex);
                }
            }
        }
        this.notifying = true;
        Object[] items = this.entityListeners.begin();
        try {
            for (int i = removeListenerBits.nextSetBit(0); i >= 0; i = removeListenerBits.nextSetBit(i + 1)) {
                ((EntityListenerData) items[i]).listener.entityRemoved(entity);
            }
            for (int i2 = addListenerBits.nextSetBit(0); i2 >= 0; i2 = addListenerBits.nextSetBit(i2 + 1)) {
                ((EntityListenerData) items[i2]).listener.entityAdded(entity);
            }
        } finally {
            addListenerBits.clear();
            removeListenerBits.clear();
            this.bitsPool.free(addListenerBits);
            this.bitsPool.free(removeListenerBits);
            this.entityListeners.end();
            this.notifying = false;
        }
    }

    private ImmutableArray<Entity> registerFamily(Family family) {
        ImmutableArray<Entity> entitiesInFamily = this.immutableFamilies.get(family);
        if (entitiesInFamily == null) {
            Array<Entity> familyEntities = new Array<>(false, 16);
            entitiesInFamily = new ImmutableArray<>(familyEntities);
            this.families.put(family, familyEntities);
            this.immutableFamilies.put(family, entitiesInFamily);
            this.entityListenerMasks.put(family, new Bits());
            Iterator<Entity> it = this.entities.iterator();
            while (it.hasNext()) {
                Entity entity = it.next();
                updateFamilyMembership(entity);
            }
        }
        return entitiesInFamily;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class EntityListenerData {
        public EntityListener listener;
        public int priority;

        private EntityListenerData() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class BitsPool extends Pool<Bits> {
        private BitsPool() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public Bits newObject() {
            return new Bits();
        }
    }
}