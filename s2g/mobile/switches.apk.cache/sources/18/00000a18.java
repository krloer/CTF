package s2g.project.game.views;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.InputMultiplexer;
import com.badlogic.gdx.Screen;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.utils.viewport.FitViewport;
import kotlin.Metadata;
import kotlin.NotImplementedError;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;
import s2g.project.game.Configuration;

/* compiled from: View.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0004\b&\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\r\u001a\u00020\u000eH\u0016J\u0010\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u0011H&J\b\u0010\u0012\u001a\u00020\u000eH\u0016J\b\u0010\u0013\u001a\u00020\u000eH&J\b\u0010\u0014\u001a\u00020\u000eH\u0016J\u0010\u0010\u0015\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u0011H\u0016J\u0018\u0010\u0016\u001a\u00020\u000e2\u0006\u0010\u0017\u001a\u00020\u00182\u0006\u0010\u0019\u001a\u00020\u0018H\u0016J\b\u0010\u001a\u001a\u00020\u000eH\u0016J\b\u0010\u001b\u001a\u00020\u000eH\u0016R\u0014\u0010\u0003\u001a\u00020\u0004X\u0084\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006R\u001a\u0010\u0007\u001a\u00020\bX\u0084\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u001c"}, d2 = {"Ls2g/project/game/views/View;", "Lcom/badlogic/gdx/Screen;", "()V", "camera", "Lcom/badlogic/gdx/graphics/OrthographicCamera;", "getCamera", "()Lcom/badlogic/gdx/graphics/OrthographicCamera;", "stage", "Lcom/badlogic/gdx/scenes/scene2d/Stage;", "getStage", "()Lcom/badlogic/gdx/scenes/scene2d/Stage;", "setStage", "(Lcom/badlogic/gdx/scenes/scene2d/Stage;)V", "dispose", BuildConfig.FLAVOR, "draw", "delta", BuildConfig.FLAVOR, "hide", "init", "pause", "render", "resize", "width", BuildConfig.FLAVOR, "height", "resume", "show", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public abstract class View implements Screen {
    private final OrthographicCamera camera = new OrthographicCamera();
    private Stage stage = new Stage(new FitViewport(Configuration.INSTANCE.getGameWidth(), Configuration.INSTANCE.getGameHeight(), this.camera));

    public abstract void draw(float f);

    public abstract void init();

    /* JADX INFO: Access modifiers changed from: protected */
    public final OrthographicCamera getCamera() {
        return this.camera;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final Stage getStage() {
        return this.stage;
    }

    protected final void setStage(Stage stage) {
        Intrinsics.checkParameterIsNotNull(stage, "<set-?>");
        this.stage = stage;
    }

    @Override // com.badlogic.gdx.Screen
    public void show() {
        Stage stage = this.stage;
        if (stage == null) {
            Intrinsics.throwNpe();
        }
        stage.setDebugAll(Configuration.INSTANCE.getDebug());
        InputMultiplexer input = new InputMultiplexer();
        input.addProcessor(this.stage);
        Input input2 = Gdx.input;
        Intrinsics.checkExpressionValueIsNotNull(input2, "Gdx.input");
        input2.setInputProcessor(input);
        init();
    }

    @Override // com.badlogic.gdx.Screen
    public void render(float delta) {
        Gdx.gl.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        Gdx.gl.glClear(16640);
        draw(delta);
        Stage stage = this.stage;
        if (stage == null) {
            Intrinsics.throwNpe();
        }
        stage.act(delta);
        Stage stage2 = this.stage;
        if (stage2 == null) {
            Intrinsics.throwNpe();
        }
        stage2.draw();
    }

    @Override // com.badlogic.gdx.Screen
    public void resize(int width, int height) {
        Stage stage = this.stage;
        if (stage == null) {
            Intrinsics.throwNpe();
        }
        stage.getViewport().update(width, height, true);
    }

    @Override // com.badlogic.gdx.Screen
    public void pause() {
        throw new NotImplementedError("An operation is not implemented: Invoked when your application is paused.");
    }

    @Override // com.badlogic.gdx.Screen
    public void resume() {
        throw new NotImplementedError("An operation is not implemented: Invoked when your application is resumed after pause.");
    }

    @Override // com.badlogic.gdx.Screen
    public void hide() {
        throw new NotImplementedError("An operation is not implemented: This method is called when another screen replaces this one.");
    }

    @Override // com.badlogic.gdx.Screen
    public void dispose() {
        this.stage.dispose();
    }
}