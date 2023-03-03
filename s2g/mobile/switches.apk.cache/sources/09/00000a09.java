package s2g.project.game.ecs.system;

import com.badlogic.ashley.core.ComponentMapper;
import com.badlogic.ashley.core.Entity;
import com.badlogic.ashley.systems.SortedIteratingSystem;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Rectangle;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.FunctionReference;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KDeclarationContainer;
import s2g.project.game.BuildConfig;
import s2g.project.game.ecs.UtilsKt;
import s2g.project.game.ecs.component.BodyComponent;
import s2g.project.game.ecs.component.TextureComponent;

/* compiled from: RenderingSystem.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\u0006\u0010\r\u001a\u00020\u000eJ\u001a\u0010\u000f\u001a\u00020\u000e2\b\u0010\u0010\u001a\u0004\u0018\u00010\u00112\u0006\u0010\u0012\u001a\u00020\u0013H\u0014J\u0018\u0010\u0014\u001a\u00020\u000e2\u0006\u0010\u0015\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\fH\u0002J\u0010\u0010\u0017\u001a\u00020\u000e2\u0006\u0010\u0012\u001a\u00020\u0013H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R2\u0010\u0007\u001a&\u0012\f\u0012\n \n*\u0004\u0018\u00010\t0\t \n*\u0012\u0012\f\u0012\n \n*\u0004\u0018\u00010\t0\t\u0018\u00010\b0\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R2\u0010\u000b\u001a&\u0012\f\u0012\n \n*\u0004\u0018\u00010\f0\f \n*\u0012\u0012\f\u0012\n \n*\u0004\u0018\u00010\f0\f\u0018\u00010\b0\bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0018"}, d2 = {"Ls2g/project/game/ecs/system/RenderingSystem;", "Lcom/badlogic/ashley/systems/SortedIteratingSystem;", "batch", "Lcom/badlogic/gdx/graphics/g2d/Batch;", "camera", "Lcom/badlogic/gdx/graphics/OrthographicCamera;", "(Lcom/badlogic/gdx/graphics/g2d/Batch;Lcom/badlogic/gdx/graphics/OrthographicCamera;)V", "bodyComponentMapper", "Lcom/badlogic/ashley/core/ComponentMapper;", "Ls2g/project/game/ecs/component/BodyComponent;", "kotlin.jvm.PlatformType", "textureComponentMapper", "Ls2g/project/game/ecs/component/TextureComponent;", "dispose", BuildConfig.FLAVOR, "processEntity", "entity", "Lcom/badlogic/ashley/core/Entity;", "deltaTime", BuildConfig.FLAVOR, "render", "bodyComponent", "textureComponent", "update", "core"}, k = 1, mv = {1, 1, 15})
/* loaded from: classes.dex */
public final class RenderingSystem extends SortedIteratingSystem {
    private final Batch batch;
    private final ComponentMapper<BodyComponent> bodyComponentMapper;
    private final OrthographicCamera camera;
    private final ComponentMapper<TextureComponent> textureComponentMapper;

    /* compiled from: RenderingSystem.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0014\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0010\u0000\u001a\u00020\u00012\u0015\u0010\u0002\u001a\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u00062\u0015\u0010\u0007\u001a\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\b¢\u0006\u0002\b\t"}, d2 = {"<anonymous>", BuildConfig.FLAVOR, "p1", "Lcom/badlogic/ashley/core/Entity;", "Lkotlin/ParameterName;", "name", "e1", "p2", "e2", "invoke"}, k = 3, mv = {1, 1, 15})
    /* renamed from: s2g.project.game.ecs.system.RenderingSystem$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static final /* synthetic */ class AnonymousClass1 extends FunctionReference implements Function2<Entity, Entity, Integer> {
        public static final AnonymousClass1 INSTANCE = new AnonymousClass1();

        AnonymousClass1() {
            super(2);
        }

        @Override // kotlin.jvm.internal.CallableReference, kotlin.reflect.KCallable
        public final String getName() {
            return "compareEntityByPosition";
        }

        @Override // kotlin.jvm.internal.CallableReference
        public final KDeclarationContainer getOwner() {
            return Reflection.getOrCreateKotlinPackage(UtilsKt.class, "core");
        }

        @Override // kotlin.jvm.internal.CallableReference
        public final String getSignature() {
            return "compareEntityByPosition(Lcom/badlogic/ashley/core/Entity;Lcom/badlogic/ashley/core/Entity;)I";
        }

        @Override // kotlin.jvm.functions.Function2
        public /* bridge */ /* synthetic */ Integer invoke(Entity entity, Entity entity2) {
            return Integer.valueOf(invoke2(entity, entity2));
        }

        /* renamed from: invoke  reason: avoid collision after fix types in other method */
        public final int invoke2(Entity p1, Entity p2) {
            Intrinsics.checkParameterIsNotNull(p1, "p1");
            Intrinsics.checkParameterIsNotNull(p2, "p2");
            return UtilsKt.compareEntityByPosition(p1, p2);
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [s2g.project.game.ecs.system.RenderingSystem$sam$java_util_Comparator$0] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public RenderingSystem(com.badlogic.gdx.graphics.g2d.Batch r4, com.badlogic.gdx.graphics.OrthographicCamera r5) {
        /*
            r3 = this;
            java.lang.String r0 = "batch"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r4, r0)
            java.lang.String r0 = "camera"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r5, r0)
            r0 = 2
            java.lang.Class[] r0 = new java.lang.Class[r0]
            java.lang.Class<s2g.project.game.ecs.component.BodyComponent> r1 = s2g.project.game.ecs.component.BodyComponent.class
            r2 = 0
            r0[r2] = r1
            java.lang.Class<s2g.project.game.ecs.component.TextureComponent> r1 = s2g.project.game.ecs.component.TextureComponent.class
            r2 = 1
            r0[r2] = r1
            com.badlogic.ashley.core.Family$Builder r0 = com.badlogic.ashley.core.Family.all(r0)
            com.badlogic.ashley.core.Family r0 = r0.get()
            s2g.project.game.ecs.system.RenderingSystem$1 r1 = s2g.project.game.ecs.system.RenderingSystem.AnonymousClass1.INSTANCE
            kotlin.jvm.functions.Function2 r1 = (kotlin.jvm.functions.Function2) r1
            if (r1 == 0) goto L2c
            s2g.project.game.ecs.system.RenderingSystem$sam$java_util_Comparator$0 r2 = new s2g.project.game.ecs.system.RenderingSystem$sam$java_util_Comparator$0
            r2.<init>()
            r1 = r2
        L2c:
            java.util.Comparator r1 = (java.util.Comparator) r1
            r3.<init>(r0, r1)
            r3.batch = r4
            r3.camera = r5
            java.lang.Class<s2g.project.game.ecs.component.BodyComponent> r0 = s2g.project.game.ecs.component.BodyComponent.class
            com.badlogic.ashley.core.ComponentMapper r0 = com.badlogic.ashley.core.ComponentMapper.getFor(r0)
            r3.bodyComponentMapper = r0
            java.lang.Class<s2g.project.game.ecs.component.TextureComponent> r0 = s2g.project.game.ecs.component.TextureComponent.class
            com.badlogic.ashley.core.ComponentMapper r0 = com.badlogic.ashley.core.ComponentMapper.getFor(r0)
            r3.textureComponentMapper = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: s2g.project.game.ecs.system.RenderingSystem.<init>(com.badlogic.gdx.graphics.g2d.Batch, com.badlogic.gdx.graphics.OrthographicCamera):void");
    }

    @Override // com.badlogic.ashley.systems.SortedIteratingSystem, com.badlogic.ashley.core.EntitySystem
    public void update(float deltaTime) {
        this.camera.update();
        this.batch.setProjectionMatrix(this.camera.combined);
        this.batch.enableBlending();
        this.batch.begin();
        super.update(deltaTime);
        this.batch.end();
    }

    @Override // com.badlogic.ashley.systems.SortedIteratingSystem
    protected void processEntity(Entity entity, float deltaTime) {
        UtilsKt.notNull(this.bodyComponentMapper.get(entity), this.textureComponentMapper.get(entity), new RenderingSystem$processEntity$1(this));
    }

    public final void dispose() {
        Texture texture;
        this.batch.dispose();
        Iterable entities = getEntities();
        Intrinsics.checkExpressionValueIsNotNull(entities, "entities");
        Iterable $this$forEach$iv = entities;
        for (Object element$iv : $this$forEach$iv) {
            Entity it = (Entity) element$iv;
            TextureComponent textureComponent = this.textureComponentMapper.get(it);
            if (textureComponent != null && (texture = textureComponent.getTexture()) != null) {
                texture.dispose();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void render(BodyComponent bodyComponent, TextureComponent textureComponent) {
        Rectangle rectShape = bodyComponent.getRectangle();
        this.batch.draw(textureComponent.getTexture(), rectShape.x, rectShape.y, rectShape.width, rectShape.height);
    }
}