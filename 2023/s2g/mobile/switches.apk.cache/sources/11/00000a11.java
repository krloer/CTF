package s2g.project.game.models;

import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.g2d.SpriteBatch;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import s2g.project.game.ecs.Engine;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: GameModel.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, d2 = {"<anonymous>", "Ls2g/project/game/ecs/Engine;", "invoke"}, k = 3, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class GameModel$engine$2 extends Lambda implements Function0<Engine> {
    final /* synthetic */ GameModel this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GameModel$engine$2(GameModel gameModel) {
        super(0);
        this.this$0 = gameModel;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Engine invoke() {
        SpriteBatch spriteBatch;
        OrthographicCamera orthographicCamera;
        Rectangle rectangle;
        spriteBatch = this.this$0.batch;
        orthographicCamera = this.this$0.camera;
        rectangle = this.this$0.screenRect;
        return new Engine(spriteBatch, orthographicCamera, rectangle);
    }
}