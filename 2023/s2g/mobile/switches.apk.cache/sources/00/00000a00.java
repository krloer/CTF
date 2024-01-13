package s2g.project.game.ecs;

import com.badlogic.ashley.core.PooledEngine;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.system.MovementSystem;
import s2g.project.game.ecs.system.RenderingSystem;
import s2g.project.game.ecs.system.SwitchSystem;

/* compiled from: Engine.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\u0018\u00002\u00020\u0001B\u001d\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJ\u0006\u0010\u000b\u001a\u00020\fR\u000e\u0010\t\u001a\u00020\nX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, d2 = {"Ls2g/project/game/ecs/Engine;", "Lcom/badlogic/ashley/core/PooledEngine;", "batch", "Lcom/badlogic/gdx/graphics/g2d/Batch;", "camera", "Lcom/badlogic/gdx/graphics/OrthographicCamera;", "screenRect", "Lcom/badlogic/gdx/math/Rectangle;", "(Lcom/badlogic/gdx/graphics/g2d/Batch;Lcom/badlogic/gdx/graphics/OrthographicCamera;Lcom/badlogic/gdx/math/Rectangle;)V", "renderingSystem", "Ls2g/project/game/ecs/system/RenderingSystem;", "dispose", BuildConfig.FLAVOR, "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class Engine extends PooledEngine {
    private final RenderingSystem renderingSystem;

    public Engine(Batch batch, OrthographicCamera camera, Rectangle screenRect) {
        Intrinsics.checkParameterIsNotNull(batch, "batch");
        Intrinsics.checkParameterIsNotNull(camera, "camera");
        Intrinsics.checkParameterIsNotNull(screenRect, "screenRect");
        this.renderingSystem = new RenderingSystem(batch, camera);
        addSystem(new MovementSystem(screenRect));
        addSystem(this.renderingSystem);
        addSystem(new SwitchSystem(screenRect));
    }

    public final void dispose() {
        this.renderingSystem.dispose();
    }
}