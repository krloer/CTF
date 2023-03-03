package s2g.project.game.ecs.system;

import com.badlogic.ashley.core.ComponentMapper;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.core.Family;
import com.badlogic.ashley.systems.IteratingSystem;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.UtilsKt;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.PositionComponent;
import s2g.project.game.ecs.component.VelocityComponent;

/* compiled from: MovementSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0007H\u0002J\u0010\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0007H\u0002J(\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\n2\u0006\u0010\u0014\u001a\u00020\f2\u0006\u0010\u000f\u001a\u00020\u00072\u0006\u0010\u0015\u001a\u00020\u0016H\u0002J\u001a\u0010\u0017\u001a\u00020\u00122\b\u0010\u0018\u001a\u0004\u0018\u00010\u00192\u0006\u0010\u0015\u001a\u00020\u0016H\u0014R2\u0010\u0005\u001a&\u0012\f\u0012\n \b*\u0004\u0018\u00010\u00070\u0007 \b*\u0012\u0012\f\u0012\n \b*\u0004\u0018\u00010\u00070\u0007\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R2\u0010\t\u001a&\u0012\f\u0012\n \b*\u0004\u0018\u00010\n0\n \b*\u0012\u0012\f\u0012\n \b*\u0004\u0018\u00010\n0\n\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R2\u0010\u000b\u001a&\u0012\f\u0012\n \b*\u0004\u0018\u00010\f0\f \b*\u0012\u0012\f\u0012\n \b*\u0004\u0018\u00010\f0\f\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u001a"}, d2 = {"Ls2g/project/game/ecs/system/MovementSystem;", "Lcom/badlogic/ashley/systems/IteratingSystem;", "screenRect", "Lcom/badlogic/gdx/math/Rectangle;", "(Lcom/badlogic/gdx/math/Rectangle;)V", "bodyComponentMapper", "Lcom/badlogic/ashley/core/ComponentMapper;", "Ls2g/project/game/ecs/component/BodyComponent;", "kotlin.jvm.PlatformType", "positionComponentMapper", "Ls2g/project/game/ecs/component/PositionComponent;", "velocityComponentMapper", "Ls2g/project/game/ecs/component/VelocityComponent;", "hasHorizontalCollision", BuildConfig.FLAVOR, "bodyComponent", "hasVerticalCollision", "move", BuildConfig.FLAVOR, "positionComponent", "velocityComponent", "deltaTime", BuildConfig.FLAVOR, "processEntity", "entity", "Lcom/badlogic/ashley/core/Entity;", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class MovementSystem extends IteratingSystem {
    private final ComponentMapper<BodyComponent> bodyComponentMapper;
    private final ComponentMapper<PositionComponent> positionComponentMapper;
    private final Rectangle screenRect;
    private final ComponentMapper<VelocityComponent> velocityComponentMapper;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MovementSystem(Rectangle screenRect) {
        super(Family.all(BodyComponent.class, PositionComponent.class, VelocityComponent.class).get());
        Intrinsics.checkParameterIsNotNull(screenRect, "screenRect");
        this.screenRect = screenRect;
        this.bodyComponentMapper = ComponentMapper.getFor(BodyComponent.class);
        this.positionComponentMapper = ComponentMapper.getFor(PositionComponent.class);
        this.velocityComponentMapper = ComponentMapper.getFor(VelocityComponent.class);
    }

    @Override // com.badlogic.ashley.systems.IteratingSystem
    protected void processEntity(Entity entity, float deltaTime) {
        UtilsKt.notNull(this.positionComponentMapper.get(entity), this.velocityComponentMapper.get(entity), this.bodyComponentMapper.get(entity), Float.valueOf(RangesKt.coerceAtMost(deltaTime, 0.25f)), new MovementSystem$processEntity$1(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void move(PositionComponent positionComponent, VelocityComponent velocityComponent, BodyComponent bodyComponent, float deltaTime) {
        float move = velocityComponent.getX() * deltaTime;
        bodyComponent.getRectangle().x += move;
        if (hasHorizontalCollision(bodyComponent)) {
            bodyComponent.getRectangle().x -= move;
        }
        if (velocityComponent.getX() != 0.0f) {
            velocityComponent.setX(0.0f);
        }
        velocityComponent.setY(velocityComponent.getY() - 10.0f);
        float jump = velocityComponent.getY() * deltaTime;
        bodyComponent.getRectangle().y += jump;
        if (hasVerticalCollision(bodyComponent)) {
            bodyComponent.getRectangle().y -= jump;
        }
    }

    private final boolean hasHorizontalCollision(BodyComponent bodyComponent) {
        return bodyComponent.getRectangle().x < this.screenRect.x || bodyComponent.getRectangle().x + bodyComponent.getRectangle().width > this.screenRect.x + this.screenRect.width;
    }

    private final boolean hasVerticalCollision(BodyComponent bodyComponent) {
        return bodyComponent.getRectangle().y < this.screenRect.y || bodyComponent.getRectangle().y + bodyComponent.getRectangle().height > this.screenRect.y + this.screenRect.height;
    }
}