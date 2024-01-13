package s2g.project.game.ecs.component;

import com.badlogic.ashley.core.Component;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;

/* compiled from: BodyComponent.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006¨\u0006\u0007"}, d2 = {"Ls2g/project/game/ecs/component/BodyComponent;", "Lcom/badlogic/ashley/core/Component;", "()V", "rectangle", "Lcom/badlogic/gdx/math/Rectangle;", "getRectangle", "()Lcom/badlogic/gdx/math/Rectangle;", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class BodyComponent implements Component {
    private final Rectangle rectangle = new Rectangle();

    public final Rectangle getRectangle() {
        return this.rectangle;
    }
}