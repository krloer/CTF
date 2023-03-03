package s2g.project.game.ecs.system;

import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.FunctionReference;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KDeclarationContainer;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.SwitchComponent;

/* compiled from: SwitchSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0015\u0010\u0002\u001a\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u00062\u0015\u0010\u0007\u001a\u00110\b¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\t2\u0015\u0010\n\u001a\u00110\u000b¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\f¢\u0006\u0002\b\r"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "p1", "Ls2g/project/game/ecs/component/SwitchComponent;", "Lkotlin/ParameterName;", "name", "switchComponent", "p2", "Ls2g/project/game/ecs/component/BodyComponent;", "bodyComponent", "p3", "Lcom/badlogic/gdx/math/Rectangle;", "screenRect", "invoke"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
final /* synthetic */ class SwitchSystem$processEntity$1 extends FunctionReference implements Function3<SwitchComponent, BodyComponent, Rectangle, Unit> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SwitchSystem$processEntity$1(SwitchSystem switchSystem) {
        super(3, switchSystem);
    }

    @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
    public final String getName() {
        return "move";
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final KDeclarationContainer getOwner() {
        return Reflection.getOrCreateKotlinClass(SwitchSystem.class);
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final String getSignature() {
        return "move(Ls2g/project/game/ecs/component/SwitchComponent;Ls2g/project/game/ecs/component/BodyComponent;Lcom/badlogic/gdx/math/Rectangle;)V";
    }

    @Override // kotlin.jvm.functions.Function3
    public /* bridge */ /* synthetic */ Unit invoke(SwitchComponent switchComponent, BodyComponent bodyComponent, Rectangle rectangle) {
        invoke2(switchComponent, bodyComponent, rectangle);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke  reason: avoid collision after fix types in other method */
    public final void invoke2(SwitchComponent p1, BodyComponent p2, Rectangle p3) {
        Intrinsics.checkParameterIsNotNull(p1, "p1");
        Intrinsics.checkParameterIsNotNull(p2, "p2");
        Intrinsics.checkParameterIsNotNull(p3, "p3");
        ((SwitchSystem) this.receiver).move(p1, p2, p3);
    }
}