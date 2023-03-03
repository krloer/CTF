package s2g.project.game.ecs.system;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.FunctionReference;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KDeclarationContainer;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.PositionComponent;
import s2g.project.game.ecs.component.VelocityComponent;

/* compiled from: MovementSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000,\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0015\u0010\u0002\u001a\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u00062\u0015\u0010\u0007\u001a\u00110\b¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\t2\u0015\u0010\n\u001a\u00110\u000b¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\f2\u0015\u0010\r\u001a\u00110\u000e¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u000f¢\u0006\u0002\b\u0010"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "p1", "Ls2g/project/game/ecs/component/PositionComponent;", "Lkotlin/ParameterName;", "name", "positionComponent", "p2", "Ls2g/project/game/ecs/component/VelocityComponent;", "velocityComponent", "p3", "Ls2g/project/game/ecs/component/BodyComponent;", "bodyComponent", "p4", BuildConfig.FLAVOR, "deltaTime", "invoke"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
final /* synthetic */ class MovementSystem$processEntity$1 extends FunctionReference implements Function4<PositionComponent, VelocityComponent, BodyComponent, Float, Unit> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public MovementSystem$processEntity$1(MovementSystem movementSystem) {
        super(4, movementSystem);
    }

    @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
    public final String getName() {
        return "move";
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final KDeclarationContainer getOwner() {
        return Reflection.getOrCreateKotlinClass(MovementSystem.class);
    }

    @Override // kotlin.jvm.internal.CallableReference
    public final String getSignature() {
        return "move(Ls2g/project/game/ecs/component/PositionComponent;Ls2g/project/game/ecs/component/VelocityComponent;Ls2g/project/game/ecs/component/BodyComponent;F)V";
    }

    @Override // kotlin.jvm.functions.Function4
    public /* bridge */ /* synthetic */ Unit invoke(PositionComponent positionComponent, VelocityComponent velocityComponent, BodyComponent bodyComponent, Float f) {
        invoke(positionComponent, velocityComponent, bodyComponent, f.floatValue());
        return Unit.INSTANCE;
    }

    public final void invoke(PositionComponent p1, VelocityComponent p2, BodyComponent p3, float p4) {
        Intrinsics.checkParameterIsNotNull(p1, "p1");
        Intrinsics.checkParameterIsNotNull(p2, "p2");
        Intrinsics.checkParameterIsNotNull(p3, "p3");
        ((MovementSystem) this.receiver).move(p1, p2, p3, p4);
    }
}