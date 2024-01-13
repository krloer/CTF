package kotlin.jvm.internal;

import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.reflect.KTypeProjection;
import s2g.project.game.BuildConfig;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: TypeReference.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\n¢\u0006\u0002\b\u0004"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "it", "Lkotlin/reflect/KTypeProjection;", "invoke"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class TypeReference$asString$args$1 extends Lambda implements Function1<KTypeProjection, String> {
    final /* synthetic */ TypeReference this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public TypeReference$asString$args$1(TypeReference typeReference) {
        super(1);
        this.this$0 = typeReference;
    }

    @Override // kotlin.jvm.functions.Function1
    public final String invoke(KTypeProjection it) {
        String asString;
        Intrinsics.checkParameterIsNotNull(it, "it");
        asString = this.this$0.asString(it);
        return asString;
    }
}