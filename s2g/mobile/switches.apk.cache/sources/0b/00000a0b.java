package s2g.project.game.ecs.system;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.FunctionReference;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KDeclarationContainer;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.TextureComponent;

/* compiled from: RenderingSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0015\u0010\u0002\u001a\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u00062\u0015\u0010\u0007\u001a\u00110\b¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\t¢\u0006\u0002\b\n"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "p1", "Ls2g/project/game/ecs/component/BodyComponent;", "Lkotlin/ParameterName;", "name", "bodyComponent", "p2", "Ls2g/project/game/ecs/component/TextureComponent;", "textureComponent", "invoke"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
final /* synthetic */ class RenderingSystem$processEntity$1 extends FunctionReference implements Function2<BodyComponent, TextureComponent, Unit> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public RenderingSystem$processEntity$1(RenderingSystem renderingSystem) {
        super(2, renderingSystem);
    }

    @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
    public final String getName() {
        return "render";
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final KDeclarationContainer getOwner() {
        return Reflection.getOrCreateKotlinClass(RenderingSystem.class);
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final String getSignature() {
        return "render(Ls2g/project/game/ecs/component/BodyComponent;Ls2g/project/game/ecs/component/TextureComponent;)V";
    }

    @Override // kotlin.jvm.functions.Function2
    public /* bridge */ /* synthetic */ Unit invoke(BodyComponent bodyComponent, TextureComponent textureComponent) {
        invoke2(bodyComponent, textureComponent);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke  reason: avoid collision after fix types in other method */
    public final void invoke2(BodyComponent p1, TextureComponent p2) {
        Intrinsics.checkParameterIsNotNull(p1, "p1");
        Intrinsics.checkParameterIsNotNull(p2, "p2");
        ((RenderingSystem) this.receiver).render(p1, p2);
    }
}