package s2g.project.game.ecs.component;

import com.badlogic.ashley.core.Component;
import kotlin.Metadata;
import s2g.project.game.BuildConfig;

/* compiled from: VelocityComponent.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\b\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0006\"\u0004\b\u000b\u0010\b¨\u0006\f"}, d2 = {"Ls2g/project/game/ecs/component/VelocityComponent;", "Lcom/badlogic/ashley/core/Component;", "()V", "x", BuildConfig.FLAVOR, "getX", "()F", "setX", "(F)V", "y", "getY", "setY", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class VelocityComponent implements Component {
    private float x;
    private float y;

    public final float getX() {
        return this.x;
    }

    public final void setX(float f) {
        this.x = f;
    }

    public final float getY() {
        return this.y;
    }

    public final void setY(float f) {
        this.y = f;
    }
}