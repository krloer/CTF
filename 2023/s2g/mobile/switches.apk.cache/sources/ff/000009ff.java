package s2g.project.game;

import com.badlogic.gdx.Game;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Graphics;
import com.badlogic.gdx.Screen;
import com.badlogic.gdx.utils.ObjectMap;
import com.kotcrab.vis.ui.VisUI;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.views.GameScreen;
import s2g.project.game.views.MainMenuScreen;
import s2g.project.game.views.View;

/* compiled from: Switches.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\b\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u001a\u0010\b\u001a\u00020\t2\u0012\u0010\n\u001a\u000e\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u0005J\b\u0010\u000b\u001a\u00020\tH\u0016J\b\u0010\f\u001a\u00020\tH\u0016J\u0006\u0010\r\u001a\u00020\tJ\b\u0010\u000e\u001a\u00020\tH\u0016J\u0010\u0010\u000f\u001a\u00020\t2\b\u0010\u0010\u001a\u0004\u0018\u00010\u0006R$\u0010\u0003\u001a\u0018\u0012\u000e\u0012\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00060\u0005\u0012\u0004\u0012\u00020\u00060\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u0004\u0018\u00010\u0006X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0011"}, d2 = {"Ls2g/project/game/Switches;", "Lcom/badlogic/gdx/Game;", "()V", "screens", "Lcom/badlogic/gdx/utils/ObjectMap;", "Ljava/lang/Class;", "Ls2g/project/game/views/View;", "view", "changeScreen", BuildConfig.FLAVOR, "key", "create", "dispose", "loadScreens", "render", "setScreen", "screen", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class Switches extends Game {
    private final ObjectMap<Class<? extends View>, View> screens = new ObjectMap<>();
    private View view;

    @Override // com.badlogic.gdx.ApplicationListener
    public void create() {
        VisUI.load();
        loadScreens();
        changeScreen(MainMenuScreen.class);
        Gdx.app.log("CONTROLLER", "SwitchesController loaded");
    }

    @Override // com.badlogic.gdx.Game, com.badlogic.gdx.ApplicationListener
    public void render() {
        Graphics graphics = Gdx.graphics;
        Intrinsics.checkExpressionValueIsNotNull(graphics, "Gdx.graphics");
        float dt = graphics.getDeltaTime();
        View view = this.view;
        if (view == null) {
            Intrinsics.throwNpe();
        }
        view.render(dt);
    }

    @Override // com.badlogic.gdx.Game, com.badlogic.gdx.ApplicationListener
    public void dispose() {
        setScreen((View) null);
        Iterable $this$forEach$iv = this.screens;
        for (Object element$iv : $this$forEach$iv) {
            ObjectMap.Entry e = (ObjectMap.Entry) element$iv;
            ((View) e.value).dispose();
        }
        this.screens.clear();
        if (VisUI.isLoaded()) {
            VisUI.dispose();
        }
    }

    public final void setScreen(View screen) {
        super.setScreen((Screen) screen);
        this.view = screen;
    }

    public final void changeScreen(Class<? extends View> cls) {
        setScreen(this.screens.get(cls));
    }

    public final void loadScreens() {
        this.screens.put(MainMenuScreen.class, new MainMenuScreen(this));
        this.screens.put(GameScreen.class, new GameScreen(this));
    }
}