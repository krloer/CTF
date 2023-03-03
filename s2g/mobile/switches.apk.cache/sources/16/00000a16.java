package s2g.project.game.views;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;
import s2g.project.game.Switches;

/* compiled from: MainMenuScreen.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0016J\b\u0010\u000b\u001a\u00020\bH\u0016J\b\u0010\f\u001a\u00020\bH\u0016J\b\u0010\r\u001a\u00020\bH\u0016J\b\u0010\u000e\u001a\u00020\bH\u0016R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006¨\u0006\u000f"}, d2 = {"Ls2g/project/game/views/MainMenuScreen;", "Ls2g/project/game/views/View;", "gameController", "Ls2g/project/game/Switches;", "(Ls2g/project/game/Switches;)V", "getGameController", "()Ls2g/project/game/Switches;", "draw", BuildConfig.FLAVOR, "delta", BuildConfig.FLAVOR, "hide", "init", "pause", "resume", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class MainMenuScreen extends View {
    private final Switches gameController;

    public MainMenuScreen(Switches gameController) {
        Intrinsics.checkParameterIsNotNull(gameController, "gameController");
        this.gameController = gameController;
    }

    public final Switches getGameController() {
        return this.gameController;
    }

    @Override // s2g.project.game.views.View
    public void draw(float delta) {
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void pause() {
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void resume() {
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void hide() {
    }

    @Override // s2g.project.game.views.View
    public void init() {
        new VisTable();
        Image bg = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("bg.png")))));
        bg.setSize(getStage().getWidth(), getStage().getHeight());
        bg.setPosition(0.0f, 0.0f);
        getStage().addActor(bg);
        Image title = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("title.png")))));
        float f = 2;
        float f2 = 6;
        title.setPosition((getStage().getWidth() / f) - (getStage().getWidth() / f2), getStage().getHeight() / 1.8f);
        title.setSize(getStage().getWidth() / 3, getStage().getWidth() / f2);
        getStage().addActor(title);
        VisTextButton btnStart = new VisTextButton("Start the game");
        btnStart.addListener(new ChangeListener() { // from class: s2g.project.game.views.MainMenuScreen$init$1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                Intrinsics.checkParameterIsNotNull(event, "event");
                Intrinsics.checkParameterIsNotNull(actor, "actor");
                MainMenuScreen.this.getGameController().changeScreen(GameScreen.class);
            }
        });
        float f3 = 4;
        btnStart.setPosition((getStage().getWidth() / f) - (getStage().getWidth() / f3), getStage().getHeight() / 3.5f);
        btnStart.setSize(getStage().getWidth() / f, 70.0f);
        btnStart.setColor(0.0f, 0.0f, 0.0f, 0.0f);
        Image btnCoverStart = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("buttonstart.png")))));
        btnCoverStart.setPosition((getStage().getWidth() / f) - (getStage().getWidth() / f3), getStage().getHeight() / 3.5f);
        btnCoverStart.setSize(getStage().getWidth() / f, 70.0f);
        getStage().addActor(btnCoverStart);
        getStage().addActor(btnStart);
        Gdx.app.log("VIEW", "Main Menu loaded");
    }
}