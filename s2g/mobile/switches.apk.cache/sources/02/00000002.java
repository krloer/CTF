package com.badlogic.ashley.core;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ComponentOperationHandler {
    private BooleanInformer delayed;
    private ComponentOperationPool operationPool = new ComponentOperationPool(null);
    private Array<ComponentOperation> operations = new Array<>();

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface BooleanInformer {
        boolean value();
    }

    public ComponentOperationHandler(BooleanInformer delayed) {
        this.delayed = delayed;
    }

    public void add(Entity entity) {
        if (this.delayed.value()) {
            ComponentOperation operation = this.operationPool.obtain();
            operation.makeAdd(entity);
            this.operations.add(operation);
            return;
        }
        entity.notifyComponentAdded();
    }

    public void remove(Entity entity) {
        if (this.delayed.value()) {
            ComponentOperation operation = this.operationPool.obtain();
            operation.makeRemove(entity);
            this.operations.add(operation);
            return;
        }
        entity.notifyComponentRemoved();
    }

    public void processOperations() {
        for (int i = 0; i < this.operations.size; i++) {
            ComponentOperation operation = this.operations.get(i);
            int i2 = AnonymousClass1.$SwitchMap$com$badlogic$ashley$core$ComponentOperationHandler$ComponentOperation$Type[operation.type.ordinal()];
            if (i2 == 1) {
                operation.entity.notifyComponentAdded();
            } else if (i2 == 2) {
                operation.entity.notifyComponentRemoved();
            }
            this.operationPool.free(operation);
        }
        this.operations.clear();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.ashley.core.ComponentOperationHandler$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$ashley$core$ComponentOperationHandler$ComponentOperation$Type = new int[ComponentOperation.Type.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$ashley$core$ComponentOperationHandler$ComponentOperation$Type[ComponentOperation.Type.Add.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$ashley$core$ComponentOperationHandler$ComponentOperation$Type[ComponentOperation.Type.Remove.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ComponentOperation implements Pool.Poolable {
        public Entity entity;
        public Type type;

        /* loaded from: classes.dex */
        public enum Type {
            Add,
            Remove
        }

        private ComponentOperation() {
        }

        /* synthetic */ ComponentOperation(AnonymousClass1 x0) {
            this();
        }

        public void makeAdd(Entity entity) {
            this.type = Type.Add;
            this.entity = entity;
        }

        public void makeRemove(Entity entity) {
            this.type = Type.Remove;
            this.entity = entity;
        }

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.entity = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ComponentOperationPool extends Pool<ComponentOperation> {
        private ComponentOperationPool() {
        }

        /* synthetic */ ComponentOperationPool(AnonymousClass1 x0) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // com.badlogic.gdx.utils.Pool
        public ComponentOperation newObject() {
            return new ComponentOperation(null);
        }
    }
}