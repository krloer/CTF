package kotlin.jvm.internal;

import kotlin.reflect.KDeclarationContainer;

/* loaded from: classes.dex */
public class FunctionReferenceImpl extends FunctionReference {
    private final String name;
    private final KDeclarationContainer owner;
    private final String signature;

    public FunctionReferenceImpl(int arity, KDeclarationContainer owner, String name, String signature) {
        super(arity);
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
}