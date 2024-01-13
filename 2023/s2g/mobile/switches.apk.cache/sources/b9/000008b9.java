package kotlin.jvm.internal;

import kotlin.reflect.KDeclarationContainer;

/* loaded from: classes.dex */
public class MutablePropertyReference2Impl extends MutablePropertyReference2 {
    private final String name;
    private final KDeclarationContainer owner;
    private final String signature;

    public MutablePropertyReference2Impl(KDeclarationContainer owner, String name, String signature) {
        this.owner = owner;
        this.name = name;
        this.signature = signature;
    }

    @Override // kotlin.jvm.internal.CallableReference
    public KDeclarationContainer getOwner() {
        return this.owner;
    }

    @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
    public String getName() {
        return this.name;
    }

    @Override // kotlin.jvm.internal.CallableReference
    public String getSignature() {
        return this.signature;
    }

    @Override // kotlin.reflect.KProperty2
    public Object get(Object receiver1, Object receiver2) {
        return getGetter().call(receiver1, receiver2);
    }

    @Override // kotlin.reflect.KMutableProperty2
    public void set(Object receiver1, Object receiver2, Object value) {
        getSetter().call(receiver1, receiver2, value);
    }
}