package s2g.project.game.ecs.system;

import com.badlogic.ashley.core.ComponentMapper;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.core.Family;
import com.badlogic.ashley.systems.IteratingSystem;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.Random;
import kotlin.ranges.IntRange;
import kotlin.ranges.RangesKt;
import s2g.project.game.BuildConfig;
import s2g.project.game.Configuration;
import s2g.project.game.ecs.UtilsKt;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.SwitchComponent;

/* compiled from: SwitchSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J \u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u0002\u001a\u00020\u0003H\u0002J\u001a\u0010\u000f\u001a\u00020\f2\b\u0010\u0010\u001a\u0004\u0018\u00010\u00112\u0006\u0010\u0012\u001a\u00020\u0013H\u0014R2\u0010\u0005\u001a&\u0012\f\u0012\n \b*\u0004\u0018\u00010\u00070\u0007 \b*\u0012\u0012\f\u0012\n \b*\u0004\u0018\u00010\u00070\u0007\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R2\u0010\t\u001a&\u0012\f\u0012\n \b*\u0004\u0018\u00010\n0\n \b*\u0012\u0012\f\u0012\n \b*\u0004\u0018\u00010\n0\n\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0014"}, d2 = {"Ls2g/project/game/ecs/system/SwitchSystem;", "Lcom/badlogic/ashley/systems/IteratingSystem;", "screenRect", "Lcom/badlogic/gdx/math/Rectangle;", "(Lcom/badlogic/gdx/math/Rectangle;)V", "bodyComponentMapper", "Lcom/badlogic/ashley/core/ComponentMapper;", "Ls2g/project/game/ecs/component/BodyComponent;", "kotlin.jvm.PlatformType", "switchComponentMapper", "Ls2g/project/game/ecs/component/SwitchComponent;", "move", BuildConfig.FLAVOR, "switchComponent", "bodyComponent", "processEntity", "entity", "Lcom/badlogic/ashley/core/Entity;", "deltaTime", BuildConfig.FLAVOR, "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class SwitchSystem extends IteratingSystem {
    private final ComponentMapper<BodyComponent> bodyComponentMapper;
    private final Rectangle screenRect;
    private final ComponentMapper<SwitchComponent> switchComponentMapper;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SwitchSystem(Rectangle screenRect) {
        super(Family.all(SwitchComponent.class, BodyComponent.class).get());
        Intrinsics.checkParameterIsNotNull(screenRect, "screenRect");
        this.screenRect = screenRect;
        this.switchComponentMapper = ComponentMapper.getFor(SwitchComponent.class);
        this.bodyComponentMapper = ComponentMapper.getFor(BodyComponent.class);
    }

    @Override // com.badlogic.ashley.systems.IteratingSystem
    protected void processEntity(Entity entity, float deltaTime) {
        UtilsKt.notNull(this.switchComponentMapper.get(entity), this.bodyComponentMapper.get(entity), this.screenRect, new SwitchSystem$processEntity$1(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void move(SwitchComponent switchComponent, BodyComponent bodyComponent, Rectangle screenRect) {
        if (switchComponent.getTouched()) {
            float f = 50;
            bodyComponent.getRectangle().x = RangesKt.random(new IntRange(50, (int) (Configuration.INSTANCE.getGameWidth() - f)), Random.Default);
            bodyComponent.getRectangle().y = RangesKt.random(new IntRange(90, (int) (Configuration.INSTANCE.getGameHeight() - f)), Random.Default);
            switchComponent.setTouched(false);
        }
    }
}