package s2g.project.game.models;

import com.badlogic.ashley.core.Component;
import com.badlogic.ashley.core.Entity;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.SpriteBatch;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Lazy;
import kotlin.LazyKt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.PropertyReference1Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KProperty;
import s2g.project.game.BuildConfig;
import s2g.project.game.Configuration;
import s2g.project.game.ecs.Engine;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.PositionComponent;
import s2g.project.game.ecs.component.SwitchComponent;
import s2g.project.game.ecs.component.TextureComponent;
import s2g.project.game.ecs.component.VelocityComponent;

/* compiled from: GameModel.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\f\n\u0002\u0010\u0002\n\u0002\b\u0007\n\u0002\u0010\u0007\n\u0002\b\u0002\u0018\u0000 82\u00020\u0001:\u00018B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\u0010\u0010*\u001a\n +*\u0004\u0018\u00010\u00190\u0019H\u0002J\u0010\u0010,\u001a\n +*\u0004\u0018\u00010\u00190\u0019H\u0002J\u0010\u0010-\u001a\n +*\u0004\u0018\u00010\u00190\u0019H\u0002J\u0006\u0010.\u001a\u00020/J\u0006\u00100\u001a\u00020/J\u0006\u00101\u001a\u00020/J\u0006\u00102\u001a\u00020/J\u0006\u00103\u001a\u00020/J\u0006\u00104\u001a\u00020/J\u000e\u00105\u001a\u00020/2\u0006\u00106\u001a\u000207R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u001b\u0010\t\u001a\u00020\n8BX\u0082\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000b\u0010\fR\u001a\u0010\u000f\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u001a\u0010\u0015\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0016\u0010\u0012\"\u0004\b\u0017\u0010\u0014R\u001a\u0010\u0018\u001a\u00020\u0019X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u001a\u0010\u001b\"\u0004\b\u001c\u0010\u001dR\u001a\u0010\u001e\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001f\u0010\u0012\"\u0004\b \u0010\u0014R\u001a\u0010!\u001a\u00020\"X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b#\u0010$\"\u0004\b%\u0010&R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010'\u001a\u00020\u0019X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b(\u0010\u001b\"\u0004\b)\u0010\u001d¨\u00069"}, d2 = {"Ls2g/project/game/models/GameModel;", BuildConfig.FLAVOR, "screenRect", "Lcom/badlogic/gdx/math/Rectangle;", "camera", "Lcom/badlogic/gdx/graphics/OrthographicCamera;", "(Lcom/badlogic/gdx/math/Rectangle;Lcom/badlogic/gdx/graphics/OrthographicCamera;)V", "batch", "Lcom/badlogic/gdx/graphics/g2d/SpriteBatch;", "engine", "Ls2g/project/game/ecs/Engine;", "getEngine", "()Ls2g/project/game/ecs/Engine;", "engine$delegate", "Lkotlin/Lazy;", "jumpPressed", BuildConfig.FLAVOR, "getJumpPressed", "()Z", "setJumpPressed", "(Z)V", "leftPressed", "getLeftPressed", "setLeftPressed", "player", "Lcom/badlogic/ashley/core/Entity;", "getPlayer", "()Lcom/badlogic/ashley/core/Entity;", "setPlayer", "(Lcom/badlogic/ashley/core/Entity;)V", "rightPressed", "getRightPressed", "setRightPressed", "score", BuildConfig.FLAVOR, "getScore", "()I", "setScore", "(I)V", "switch", "getSwitch", "setSwitch", "createBG", "kotlin.jvm.PlatformType", "createHero", "createSwitch", "dispose", BuildConfig.FLAVOR, "hide", "init", "jump", "moveLeft", "moveRight", "render", "delta", BuildConfig.FLAVOR, "Companion", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class GameModel {
    private final SpriteBatch batch;
    private final OrthographicCamera camera;
    private final Lazy engine$delegate;
    private boolean jumpPressed;
    private boolean leftPressed;
    public Entity player;
    private boolean rightPressed;
    private int score;
    private final Rectangle screenRect;

    /* renamed from: switch  reason: not valid java name */
    public Entity f3switch;
    static final /* synthetic */ KProperty[] $$delegatedProperties = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(GameModel.class), "engine", "getEngine()Ls2g/project/game/ecs/Engine;"))};
    public static final Companion Companion = new Companion(null);
    private static final float WIDTH = Configuration.INSTANCE.getGameWidth();
    private static final float HEIGHT = Configuration.INSTANCE.getGameHeight();

    private final Engine getEngine() {
        Lazy lazy = this.engine$delegate;
        KProperty kProperty = $$delegatedProperties[0];
        return (Engine) lazy.getValue();
    }

    public GameModel(Rectangle screenRect, OrthographicCamera camera) {
        Intrinsics.checkParameterIsNotNull(screenRect, "screenRect");
        Intrinsics.checkParameterIsNotNull(camera, "camera");
        this.screenRect = screenRect;
        this.camera = camera;
        this.batch = new SpriteBatch();
        this.engine$delegate = LazyKt.lazy(new GameModel$engine$2(this));
    }

    public final Entity getPlayer() {
        Entity entity = this.player;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        return entity;
    }

    public final void setPlayer(Entity entity) {
        Intrinsics.checkParameterIsNotNull(entity, "<set-?>");
        this.player = entity;
    }

    public final Entity getSwitch() {
        Entity entity = this.f3switch;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("switch");
        }
        return entity;
    }

    public final void setSwitch(Entity entity) {
        Intrinsics.checkParameterIsNotNull(entity, "<set-?>");
        this.f3switch = entity;
    }

    public final boolean getLeftPressed() {
        return this.leftPressed;
    }

    public final void setLeftPressed(boolean z) {
        this.leftPressed = z;
    }

    public final boolean getRightPressed() {
        return this.rightPressed;
    }

    public final void setRightPressed(boolean z) {
        this.rightPressed = z;
    }

    public final boolean getJumpPressed() {
        return this.jumpPressed;
    }

    public final void setJumpPressed(boolean z) {
        this.jumpPressed = z;
    }

    public final int getScore() {
        return this.score;
    }

    public final void setScore(int i) {
        this.score = i;
    }

    public final void init() {
        getEngine().addEntity(createBG());
        Entity createSwitch = createSwitch();
        Intrinsics.checkExpressionValueIsNotNull(createSwitch, "createSwitch()");
        this.f3switch = createSwitch;
        Engine engine = getEngine();
        Entity entity = this.f3switch;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("switch");
        }
        engine.addEntity(entity);
        Entity createHero = createHero();
        Intrinsics.checkExpressionValueIsNotNull(createHero, "createHero()");
        this.player = createHero;
        Engine engine2 = getEngine();
        Entity entity2 = this.player;
        if (entity2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        engine2.addEntity(entity2);
        Gdx.app.log("MODEL", "Engine loaded");
    }

    public final void render(float delta) {
        Gdx.gl.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        Gdx.gl.glClear(GL20.GL_COLOR_BUFFER_BIT);
        Entity entity = this.player;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        Rectangle rectangle = ((BodyComponent) entity.getComponent(BodyComponent.class)).getRectangle();
        Entity entity2 = this.f3switch;
        if (entity2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("switch");
        }
        if (rectangle.contains(((BodyComponent) entity2.getComponent(BodyComponent.class)).getRectangle())) {
            Entity entity3 = this.f3switch;
            if (entity3 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("switch");
            }
            ((SwitchComponent) entity3.getComponent(SwitchComponent.class)).setTouched(true);
            this.score++;
        }
        if (this.leftPressed) {
            moveLeft();
        }
        if (this.rightPressed) {
            moveRight();
        }
        if (this.jumpPressed) {
            jump();
        }
        getEngine().update(delta);
    }

    public final void jump() {
        Entity entity = this.player;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        ((VelocityComponent) entity.getComponent(VelocityComponent.class)).setY(300.0f);
    }

    public final void moveLeft() {
        Entity entity = this.player;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        ((VelocityComponent) entity.getComponent(VelocityComponent.class)).setX(-200.0f);
    }

    public final void moveRight() {
        Entity entity = this.player;
        if (entity == null) {
            Intrinsics.throwUninitializedPropertyAccessException("player");
        }
        ((VelocityComponent) entity.getComponent(VelocityComponent.class)).setX(200.0f);
    }

    public final void dispose() {
        getEngine().dispose();
    }

    public final void hide() {
        getEngine().removeAllEntities();
        getEngine().clearPools();
    }

    private final Entity createBG() {
        Entity entity = getEngine().createEntity();
        Component createComponent = getEngine().createComponent(PositionComponent.class);
        ((PositionComponent) createComponent).setZ(0.0f);
        entity.add(createComponent);
        Component createComponent2 = getEngine().createComponent(BodyComponent.class);
        BodyComponent $this$apply = (BodyComponent) createComponent2;
        $this$apply.getRectangle().setWidth(WIDTH);
        $this$apply.getRectangle().setHeight(HEIGHT);
        entity.add(createComponent2);
        Component createComponent3 = getEngine().createComponent(TextureComponent.class);
        ((TextureComponent) createComponent3).setTexture(new Texture("bg.png"));
        entity.add(createComponent3);
        return entity;
    }

    private final Entity createHero() {
        Entity entity = getEngine().createEntity();
        Component createComponent = getEngine().createComponent(PositionComponent.class);
        ((PositionComponent) createComponent).setZ(1.0f);
        entity.add(createComponent);
        Component createComponent2 = getEngine().createComponent(BodyComponent.class);
        BodyComponent $this$apply = (BodyComponent) createComponent2;
        $this$apply.getRectangle().setWidth(100.0f);
        $this$apply.getRectangle().setHeight(100.0f);
        $this$apply.getRectangle().x = (Configuration.INSTANCE.getGameWidth() / 2) - 50.0f;
        entity.add(createComponent2);
        Component createComponent3 = getEngine().createComponent(TextureComponent.class);
        ((TextureComponent) createComponent3).setTexture(new Texture("player.png"));
        entity.add(createComponent3);
        Component createComponent4 = getEngine().createComponent(VelocityComponent.class);
        VelocityComponent $this$apply2 = (VelocityComponent) createComponent4;
        $this$apply2.setX(-80.0f);
        $this$apply2.setY(-100.0f);
        entity.add(createComponent4);
        return entity;
    }

    private final Entity createSwitch() {
        Entity entity = getEngine().createEntity();
        Component createComponent = getEngine().createComponent(PositionComponent.class);
        PositionComponent $this$apply = (PositionComponent) createComponent;
        $this$apply.setZ(1.0f);
        entity.add(createComponent);
        Component createComponent2 = getEngine().createComponent(SwitchComponent.class);
        SwitchComponent $this$apply2 = (SwitchComponent) createComponent2;
        $this$apply2.setTouched(false);
        entity.add(createComponent2);
        Component createComponent3 = getEngine().createComponent(BodyComponent.class);
        BodyComponent $this$apply3 = (BodyComponent) createComponent3;
        $this$apply3.getRectangle().setWidth(40.0f);
        $this$apply3.getRectangle().setHeight(40.0f);
        float f = 2;
        $this$apply3.getRectangle().y = Configuration.INSTANCE.getGameHeight() / f;
        $this$apply3.getRectangle().x = (Configuration.INSTANCE.getGameWidth() / f) - 20.0f;
        entity.add(createComponent3);
        Component createComponent4 = getEngine().createComponent(TextureComponent.class);
        TextureComponent $this$apply4 = (TextureComponent) createComponent4;
        $this$apply4.setTexture(new Texture("switch.png"));
        entity.add(createComponent4);
        return entity;
    }

    /* compiled from: GameModel.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0006"}, d2 = {"Ls2g/project/game/models/GameModel$Companion;", BuildConfig.FLAVOR, "()V", "HEIGHT", BuildConfig.FLAVOR, "WIDTH", "core"}, k = 1, mv = {1, 1, 15})
    /* loaded from: classes.dex */
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker $constructor_marker) {
            this();
        }
    }
}