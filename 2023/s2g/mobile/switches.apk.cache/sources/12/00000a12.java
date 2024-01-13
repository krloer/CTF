package s2g.project.game.views;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable;
import com.badlogic.gdx.utils.StringBuilder;
import com.badlogic.gdx.utils.viewport.Viewport;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import java.nio.charset.Charset;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;
import s2g.project.game.BuildConfig;
import s2g.project.game.Configuration;
import s2g.project.game.Switches;
import s2g.project.game.ecs.UtilsKt;
import s2g.project.game.models.GameModel;

/* compiled from: GameScreen.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\b\u0010\u0014\u001a\u00020\u0015H\u0016J\u0010\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0017\u001a\u00020\u0018H\u0016J\b\u0010\u0019\u001a\u00020\u0015H\u0016J\b\u0010\u001a\u001a\u00020\u0015H\u0016J\b\u0010\u001b\u001a\u00020\u0015H\u0016J\u0018\u0010\u001c\u001a\u00020\u00152\u0006\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u001eH\u0016J\b\u0010 \u001a\u00020\u0015H\u0016R\u001a\u0010\u0005\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\nR\u000e\u0010\u000b\u001a\u00020\fX\u0082\u0004¢\u0006\u0002\n\u0000R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0010\u0010\b\"\u0004\b\u0011\u0010\nR\u000e\u0010\u0012\u001a\u00020\u0013X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006!"}, d2 = {"Ls2g/project/game/views/GameScreen;", "Ls2g/project/game/views/View;", "gameController", "Ls2g/project/game/Switches;", "(Ls2g/project/game/Switches;)V", "flag", "Lcom/kotcrab/vis/ui/widget/VisLabel;", "getFlag", "()Lcom/kotcrab/vis/ui/widget/VisLabel;", "setFlag", "(Lcom/kotcrab/vis/ui/widget/VisLabel;)V", "game", "Ls2g/project/game/models/GameModel;", "getGameController", "()Ls2g/project/game/Switches;", "score", "getScore", "setScore", "screenRect", "Lcom/badlogic/gdx/math/Rectangle;", "dispose", BuildConfig.FLAVOR, "draw", "delta", BuildConfig.FLAVOR, "hide", "init", "pause", "resize", "width", BuildConfig.FLAVOR, "height", "resume", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class GameScreen extends View {
    private VisLabel flag;
    private final GameModel game;
    private final Switches gameController;
    private VisLabel score;
    private final Rectangle screenRect;

    public GameScreen(Switches gameController) {
        Intrinsics.checkParameterIsNotNull(gameController, "gameController");
        this.gameController = gameController;
        float f = 2;
        this.screenRect = new Rectangle(0.0f, 0.0f, Configuration.INSTANCE.getGameWidth() * f, Configuration.INSTANCE.getGameHeight() * f);
        this.game = new GameModel(this.screenRect, getCamera());
        this.flag = new VisLabel(BuildConfig.FLAVOR);
        this.score = new VisLabel(BuildConfig.FLAVOR);
    }

    public static final /* synthetic */ GameModel access$getGame$p(GameScreen $this) {
        return $this.game;
    }

    public final Switches getGameController() {
        return this.gameController;
    }

    public final VisLabel getFlag() {
        return this.flag;
    }

    public final void setFlag(VisLabel visLabel) {
        Intrinsics.checkParameterIsNotNull(visLabel, "<set-?>");
        this.flag = visLabel;
    }

    public final VisLabel getScore() {
        return this.score;
    }

    public final void setScore(VisLabel visLabel) {
        Intrinsics.checkParameterIsNotNull(visLabel, "<set-?>");
        this.score = visLabel;
    }

    @Override // s2g.project.game.views.View
    public void draw(float delta) {
        this.game.render(delta);
        this.score.setText(String.valueOf(this.game.getScore()));
        int score = this.game.getScore();
        if (112 <= score && 5554 >= score) {
            StringBuilder text = this.flag.getText();
            Intrinsics.checkExpressionValueIsNotNull(text, "flag.text");
            if (!StringsKt.startsWith$default((CharSequence) text, (CharSequence) "S2G", false, 2, (Object) null)) {
                String score2 = StringsKt.repeat(StringsKt.padStart(String.valueOf(this.game.getScore()), 4, '0'), 4);
                Charset charset = Charsets.UTF_8;
                if (score2 == null) {
                    throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                }
                byte[] bytes = score2.getBytes(charset);
                Intrinsics.checkExpressionValueIsNotNull(bytes, "(this as java.lang.String).getBytes(charset)");
                SecretKeySpec key = new SecretKeySpec(bytes, "AES");
                byte[] bytes2 = "1234567890123456".getBytes(Charsets.UTF_8);
                Intrinsics.checkExpressionValueIsNotNull(bytes2, "(this as java.lang.String).getBytes(charset)");
                IvParameterSpec iv = new IvParameterSpec(bytes2);
                try {
                    String text2 = UtilsKt.decrypt("AES/CBC/PKCS5Padding", "+vrXfpBAA9wGyxmX2pZksxLt+hFnJFwUgLJJGghdLwueqPibuOl97qYH2U5Q19De", key, iv);
                    if (StringsKt.startsWith$default(text2, "S2G", false, 2, (Object) null)) {
                        this.flag.setText(text2);
                    }
                    System.out.println((Object) text2);
                } catch (Exception e) {
                }
            }
        }
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void resize(int width, int height) {
        super.resize(width, height);
        Rectangle rectangle = this.screenRect;
        Stage stage = getStage();
        if (stage == null) {
            Intrinsics.throwNpe();
        }
        Viewport viewport = stage.getViewport();
        Intrinsics.checkExpressionValueIsNotNull(viewport, "stage!!.viewport");
        rectangle.width = viewport.getWorldWidth();
        Rectangle rectangle2 = this.screenRect;
        Stage stage2 = getStage();
        if (stage2 == null) {
            Intrinsics.throwNpe();
        }
        Viewport viewport2 = stage2.getViewport();
        Intrinsics.checkExpressionValueIsNotNull(viewport2, "stage!!.viewport");
        rectangle2.height = viewport2.getWorldHeight();
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void dispose() {
        super.dispose();
        this.game.dispose();
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void pause() {
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void resume() {
    }

    @Override // s2g.project.game.views.View, com.badlogic.gdx.Screen
    public void hide() {
        this.game.hide();
    }

    @Override // s2g.project.game.views.View
    public void init() {
        VisTable table = new VisTable();
        float f = 2;
        this.score.setPosition((Configuration.INSTANCE.getGameWidth() / f) - 10.0f, Configuration.INSTANCE.getGameHeight() - 30.0f);
        this.score.setColor(0.0f, 0.0f, 0.0f, 1.0f);
        this.score.setFontScale(2.0f);
        getStage().addActor(this.score);
        this.flag.setColor(0.0f, 0.0f, 0.0f, 1.0f);
        this.flag.setAlignment(1);
        table.columnDefaults(0).pad(10.0f);
        table.columnDefaults(1).pad(10.0f);
        table.setFillParent(true);
        table.add((VisTable) this.flag).size(getStage().getWidth() / f, 100.0f);
        table.row();
        getStage().addActor(table);
        VisTextButton btnLeft = new VisTextButton("<");
        btnLeft.addListener(new InputListener() { // from class: s2g.project.game.views.GameScreen$init$1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setLeftPressed(true);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setLeftPressed(false);
            }
        });
        VisTextButton btnRight = new VisTextButton(">");
        btnRight.addListener(new InputListener() { // from class: s2g.project.game.views.GameScreen$init$2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setRightPressed(true);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setRightPressed(false);
            }
        });
        VisTextButton btnJump = new VisTextButton("jump");
        btnJump.addListener(new InputListener() { // from class: s2g.project.game.views.GameScreen$init$3
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setJumpPressed(true);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                GameScreen.access$getGame$p(GameScreen.this).setJumpPressed(false);
            }
        });
        btnLeft.setPosition(20.0f, 20.0f);
        btnRight.setPosition(140.0f, 20.0f);
        btnJump.setPosition(Configuration.INSTANCE.getGameWidth() - 100.0f, 20.0f);
        btnLeft.setSize(80.0f, 80.0f);
        btnRight.setSize(80.0f, 80.0f);
        btnJump.setSize(80.0f, 80.0f);
        btnLeft.setColor(0.0f, 0.0f, 0.0f, 0.0f);
        btnRight.setColor(0.0f, 0.0f, 0.0f, 0.0f);
        btnJump.setColor(0.0f, 0.0f, 0.0f, 0.0f);
        Image btnCoverLeft = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("buttonleft.png")))));
        btnCoverLeft.setSize(80.0f, 80.0f);
        btnCoverLeft.setPosition(20.0f, 20.0f);
        getStage().addActor(btnCoverLeft);
        Image btnCoverRight = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("buttonright.png")))));
        btnCoverRight.setSize(80.0f, 80.0f);
        btnCoverRight.setPosition(140.0f, 20.0f);
        getStage().addActor(btnCoverRight);
        Image btnCoverJump = new Image(new TextureRegionDrawable(new TextureRegion(new Texture(Gdx.files.internal("buttonjump.png")))));
        btnCoverJump.setSize(80.0f, 80.0f);
        btnCoverJump.setPosition(Configuration.INSTANCE.getGameWidth() - 100.0f, 20.0f);
        getStage().addActor(btnCoverJump);
        getStage().addActor(btnLeft);
        getStage().addActor(btnRight);
        getStage().addActor(btnJump);
        Gdx.app.log("VIEW", "Game loaded");
        getCamera().setToOrtho(false, Configuration.INSTANCE.getGameWidth(), Configuration.INSTANCE.getGameHeight());
        this.game.init();
    }
}