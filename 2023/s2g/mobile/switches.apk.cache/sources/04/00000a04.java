package s2g.project.game.ecs.component;

import com.badlogic.ashley.core.Component;
import kotlin.Metadata;
import s2g.project.game.BuildConfig;

/* compiled from: SwitchComponent.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\b¨\u0006\t"}, d2 = {"Ls2g/project/game/ecs/component/SwitchComponent;", "Lcom/badlogic/ashley/core/Component;", "()V", "touched", BuildConfig.FLAVOR, "getTouched", "()Z", "setTouched", "(Z)V", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class SwitchComponent implements Component {
    private boolean touched;

    public final boolean getTouched() {
        return this.touched;
    }

    public final void setTouched(boolean z) {
        this.touched = z;
    }
}