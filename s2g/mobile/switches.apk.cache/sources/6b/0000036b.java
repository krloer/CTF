package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.InputAdapter;
import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.SpriteBatch;
import com.badlogic.gdx.graphics.glutils.ShapeRenderer;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.Scaling;
import com.badlogic.gdx.utils.SnapshotArray;
import com.badlogic.gdx.utils.viewport.ScalingViewport;
import com.badlogic.gdx.utils.viewport.Viewport;

/* loaded from: classes.dex */
public class Stage extends InputAdapter implements Disposable {
    static boolean debug;
    private boolean actionsRequestRendering;
    private final Batch batch;
    private boolean debugAll;
    private final Color debugColor;
    private boolean debugInvisible;
    private boolean debugParentUnderMouse;
    private ShapeRenderer debugShapes;
    private Table.Debug debugTableUnderMouse;
    private boolean debugUnderMouse;
    private Actor keyboardFocus;
    private Actor mouseOverActor;
    private int mouseScreenX;
    private int mouseScreenY;
    private boolean ownsBatch;
    private final Actor[] pointerOverActors;
    private final int[] pointerScreenX;
    private final int[] pointerScreenY;
    private final boolean[] pointerTouched;
    private Group root;
    private Actor scrollFocus;
    private final Vector2 tempCoords;
    final SnapshotArray<TouchFocus> touchFocuses;
    private Viewport viewport;

    public Stage() {
        this(new ScalingViewport(Scaling.stretch, Gdx.graphics.getWidth(), Gdx.graphics.getHeight(), new OrthographicCamera()), new SpriteBatch());
        this.ownsBatch = true;
    }

    public Stage(Viewport viewport) {
        this(viewport, new SpriteBatch());
        this.ownsBatch = true;
    }

    public Stage(Viewport viewport, Batch batch) {
        this.tempCoords = new Vector2();
        this.pointerOverActors = new Actor[20];
        this.pointerTouched = new boolean[20];
        this.pointerScreenX = new int[20];
        this.pointerScreenY = new int[20];
        this.touchFocuses = new SnapshotArray<>(true, 4, TouchFocus.class);
        this.actionsRequestRendering = true;
        this.debugTableUnderMouse = Table.Debug.none;
        this.debugColor = new Color(0.0f, 1.0f, 0.0f, 0.85f);
        if (viewport == null) {
            throw new IllegalArgumentException("viewport cannot be null.");
        }
        if (batch == null) {
            throw new IllegalArgumentException("batch cannot be null.");
        }
        this.viewport = viewport;
        this.batch = batch;
        this.root = new Group();
        this.root.setStage(this);
        viewport.update(Gdx.graphics.getWidth(), Gdx.graphics.getHeight(), true);
    }

    public void draw() {
        Camera camera = this.viewport.getCamera();
        camera.update();
        if (this.root.isVisible()) {
            Batch batch = this.batch;
            batch.setProjectionMatrix(camera.combined);
            batch.begin();
            this.root.draw(batch, 1.0f);
            batch.end();
            if (debug) {
                drawDebug();
            }
        }
    }

    private void drawDebug() {
        if (this.debugShapes == null) {
            this.debugShapes = new ShapeRenderer();
            this.debugShapes.setAutoShapeType(true);
        }
        if (this.debugUnderMouse || this.debugParentUnderMouse || this.debugTableUnderMouse != Table.Debug.none) {
            screenToStageCoordinates(this.tempCoords.set(Gdx.input.getX(), Gdx.input.getY()));
            Actor actor = hit(this.tempCoords.x, this.tempCoords.y, true);
            if (actor == null) {
                return;
            }
            if (this.debugParentUnderMouse && actor.parent != null) {
                actor = actor.parent;
            }
            if (this.debugTableUnderMouse == Table.Debug.none) {
                actor.setDebug(true);
            } else {
                while (actor != null && !(actor instanceof Table)) {
                    actor = actor.parent;
                }
                if (actor == null) {
                    return;
                }
                ((Table) actor).debug(this.debugTableUnderMouse);
            }
            if (this.debugAll && (actor instanceof Group)) {
                ((Group) actor).debugAll();
            }
            disableDebug(this.root, actor);
        } else if (this.debugAll) {
            this.root.debugAll();
        }
        Gdx.gl.glEnable(GL20.GL_BLEND);
        this.debugShapes.setProjectionMatrix(this.viewport.getCamera().combined);
        this.debugShapes.begin();
        this.root.drawDebug(this.debugShapes);
        this.debugShapes.end();
        Gdx.gl.glDisable(GL20.GL_BLEND);
    }

    private void disableDebug(Actor actor, Actor except) {
        if (actor == except) {
            return;
        }
        actor.setDebug(false);
        if (actor instanceof Group) {
            SnapshotArray<Actor> children = ((Group) actor).children;
            int n = children.size;
            for (int i = 0; i < n; i++) {
                disableDebug(children.get(i), except);
            }
        }
    }

    public void act() {
        act(Math.min(Gdx.graphics.getDeltaTime(), 0.033333335f));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void act(float delta) {
        int n = this.pointerOverActors.length;
        for (int pointer = 0; pointer < n; pointer++) {
            Actor[] actorArr = this.pointerOverActors;
            Actor overLast = actorArr[pointer];
            if (!this.pointerTouched[pointer]) {
                if (overLast != null) {
                    actorArr[pointer] = null;
                    screenToStageCoordinates(this.tempCoords.set(this.pointerScreenX[pointer], this.pointerScreenY[pointer]));
                    InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
                    event.setType(InputEvent.Type.exit);
                    event.setStage(this);
                    event.setStageX(this.tempCoords.x);
                    event.setStageY(this.tempCoords.y);
                    event.setRelatedActor(overLast);
                    event.setPointer(pointer);
                    overLast.fire(event);
                    Pools.free(event);
                }
            } else {
                actorArr[pointer] = fireEnterAndExit(overLast, this.pointerScreenX[pointer], this.pointerScreenY[pointer], pointer);
            }
        }
        Application.ApplicationType type = Gdx.app.getType();
        if (type == Application.ApplicationType.Desktop || type == Application.ApplicationType.Applet || type == Application.ApplicationType.WebGL) {
            this.mouseOverActor = fireEnterAndExit(this.mouseOverActor, this.mouseScreenX, this.mouseScreenY, -1);
        }
        this.root.act(delta);
    }

    private Actor fireEnterAndExit(Actor overLast, int screenX, int screenY, int pointer) {
        screenToStageCoordinates(this.tempCoords.set(screenX, screenY));
        Actor over = hit(this.tempCoords.x, this.tempCoords.y, true);
        if (over == overLast) {
            return overLast;
        }
        if (overLast != null) {
            InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
            event.setStage(this);
            event.setStageX(this.tempCoords.x);
            event.setStageY(this.tempCoords.y);
            event.setPointer(pointer);
            event.setType(InputEvent.Type.exit);
            event.setRelatedActor(over);
            overLast.fire(event);
            Pools.free(event);
        }
        if (over != null) {
            InputEvent event2 = (InputEvent) Pools.obtain(InputEvent.class);
            event2.setStage(this);
            event2.setStageX(this.tempCoords.x);
            event2.setStageY(this.tempCoords.y);
            event2.setPointer(pointer);
            event2.setType(InputEvent.Type.enter);
            event2.setRelatedActor(overLast);
            over.fire(event2);
            Pools.free(event2);
        }
        return over;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDown(int screenX, int screenY, int pointer, int button) {
        if (isInsideViewport(screenX, screenY)) {
            this.pointerTouched[pointer] = true;
            this.pointerScreenX[pointer] = screenX;
            this.pointerScreenY[pointer] = screenY;
            screenToStageCoordinates(this.tempCoords.set(screenX, screenY));
            InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
            event.setType(InputEvent.Type.touchDown);
            event.setStage(this);
            event.setStageX(this.tempCoords.x);
            event.setStageY(this.tempCoords.y);
            event.setPointer(pointer);
            event.setButton(button);
            Actor target = hit(this.tempCoords.x, this.tempCoords.y, true);
            if (target == null) {
                if (this.root.getTouchable() == Touchable.enabled) {
                    this.root.fire(event);
                }
            } else {
                target.fire(event);
            }
            boolean handled = event.isHandled();
            Pools.free(event);
            return handled;
        }
        return false;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchDragged(int screenX, int screenY, int pointer) {
        this.pointerScreenX[pointer] = screenX;
        this.pointerScreenY[pointer] = screenY;
        this.mouseScreenX = screenX;
        this.mouseScreenY = screenY;
        if (this.touchFocuses.size == 0) {
            return false;
        }
        screenToStageCoordinates(this.tempCoords.set(screenX, screenY));
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setType(InputEvent.Type.touchDragged);
        event.setStage(this);
        event.setStageX(this.tempCoords.x);
        event.setStageY(this.tempCoords.y);
        event.setPointer(pointer);
        SnapshotArray<TouchFocus> touchFocuses = this.touchFocuses;
        TouchFocus[] focuses = touchFocuses.begin();
        int n = touchFocuses.size;
        for (int i = 0; i < n; i++) {
            TouchFocus focus = focuses[i];
            if (focus.pointer == pointer && touchFocuses.contains(focus, true)) {
                event.setTarget(focus.target);
                event.setListenerActor(focus.listenerActor);
                if (focus.listener.handle(event)) {
                    event.handle();
                }
            }
        }
        touchFocuses.end();
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean touchUp(int screenX, int screenY, int pointer, int button) {
        this.pointerTouched[pointer] = false;
        this.pointerScreenX[pointer] = screenX;
        this.pointerScreenY[pointer] = screenY;
        if (this.touchFocuses.size == 0) {
            return false;
        }
        screenToStageCoordinates(this.tempCoords.set(screenX, screenY));
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setType(InputEvent.Type.touchUp);
        event.setStage(this);
        event.setStageX(this.tempCoords.x);
        event.setStageY(this.tempCoords.y);
        event.setPointer(pointer);
        event.setButton(button);
        SnapshotArray<TouchFocus> touchFocuses = this.touchFocuses;
        TouchFocus[] focuses = touchFocuses.begin();
        int n = touchFocuses.size;
        for (int i = 0; i < n; i++) {
            TouchFocus focus = focuses[i];
            if (focus.pointer == pointer && focus.button == button && touchFocuses.removeValue(focus, true)) {
                event.setTarget(focus.target);
                event.setListenerActor(focus.listenerActor);
                if (focus.listener.handle(event)) {
                    event.handle();
                }
                Pools.free(focus);
            }
        }
        touchFocuses.end();
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean mouseMoved(int screenX, int screenY) {
        this.mouseScreenX = screenX;
        this.mouseScreenY = screenY;
        if (isInsideViewport(screenX, screenY)) {
            screenToStageCoordinates(this.tempCoords.set(screenX, screenY));
            InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
            event.setStage(this);
            event.setType(InputEvent.Type.mouseMoved);
            event.setStageX(this.tempCoords.x);
            event.setStageY(this.tempCoords.y);
            Actor target = hit(this.tempCoords.x, this.tempCoords.y, true);
            if (target == null) {
                target = this.root;
            }
            target.fire(event);
            boolean handled = event.isHandled();
            Pools.free(event);
            return handled;
        }
        return false;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean scrolled(float amountX, float amountY) {
        Actor target = this.scrollFocus;
        if (target == null) {
            target = this.root;
        }
        screenToStageCoordinates(this.tempCoords.set(this.mouseScreenX, this.mouseScreenY));
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setStage(this);
        event.setType(InputEvent.Type.scrolled);
        event.setScrollAmountX(amountX);
        event.setScrollAmountY(amountY);
        event.setStageX(this.tempCoords.x);
        event.setStageY(this.tempCoords.y);
        target.fire(event);
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyDown(int keyCode) {
        Actor target = this.keyboardFocus;
        if (target == null) {
            target = this.root;
        }
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setStage(this);
        event.setType(InputEvent.Type.keyDown);
        event.setKeyCode(keyCode);
        target.fire(event);
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyUp(int keyCode) {
        Actor target = this.keyboardFocus;
        if (target == null) {
            target = this.root;
        }
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setStage(this);
        event.setType(InputEvent.Type.keyUp);
        event.setKeyCode(keyCode);
        target.fire(event);
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    @Override // com.badlogic.gdx.InputAdapter, com.badlogic.gdx.InputProcessor
    public boolean keyTyped(char character) {
        Actor target = this.keyboardFocus;
        if (target == null) {
            target = this.root;
        }
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setStage(this);
        event.setType(InputEvent.Type.keyTyped);
        event.setCharacter(character);
        target.fire(event);
        boolean handled = event.isHandled();
        Pools.free(event);
        return handled;
    }

    public void addTouchFocus(EventListener listener, Actor listenerActor, Actor target, int pointer, int button) {
        TouchFocus focus = (TouchFocus) Pools.obtain(TouchFocus.class);
        focus.listenerActor = listenerActor;
        focus.target = target;
        focus.listener = listener;
        focus.pointer = pointer;
        focus.button = button;
        this.touchFocuses.add(focus);
    }

    public void removeTouchFocus(EventListener listener, Actor listenerActor, Actor target, int pointer, int button) {
        SnapshotArray<TouchFocus> touchFocuses = this.touchFocuses;
        for (int i = touchFocuses.size - 1; i >= 0; i--) {
            TouchFocus focus = touchFocuses.get(i);
            if (focus.listener == listener && focus.listenerActor == listenerActor && focus.target == target && focus.pointer == pointer && focus.button == button) {
                touchFocuses.removeIndex(i);
                Pools.free(focus);
            }
        }
    }

    public void cancelTouchFocus(Actor listenerActor) {
        InputEvent event = null;
        SnapshotArray<TouchFocus> touchFocuses = this.touchFocuses;
        TouchFocus[] items = touchFocuses.begin();
        int n = touchFocuses.size;
        for (int i = 0; i < n; i++) {
            TouchFocus focus = items[i];
            if (focus.listenerActor == listenerActor && touchFocuses.removeValue(focus, true)) {
                if (event == null) {
                    event = (InputEvent) Pools.obtain(InputEvent.class);
                    event.setStage(this);
                    event.setType(InputEvent.Type.touchUp);
                    event.setStageX(-2.14748365E9f);
                    event.setStageY(-2.14748365E9f);
                }
                event.setTarget(focus.target);
                event.setListenerActor(focus.listenerActor);
                event.setPointer(focus.pointer);
                event.setButton(focus.button);
                focus.listener.handle(event);
            }
        }
        touchFocuses.end();
        if (event != null) {
            Pools.free(event);
        }
    }

    public void cancelTouchFocus() {
        cancelTouchFocusExcept(null, null);
    }

    public void cancelTouchFocusExcept(EventListener exceptListener, Actor exceptActor) {
        InputEvent event = (InputEvent) Pools.obtain(InputEvent.class);
        event.setStage(this);
        event.setType(InputEvent.Type.touchUp);
        event.setStageX(-2.14748365E9f);
        event.setStageY(-2.14748365E9f);
        SnapshotArray<TouchFocus> touchFocuses = this.touchFocuses;
        TouchFocus[] items = touchFocuses.begin();
        int n = touchFocuses.size;
        for (int i = 0; i < n; i++) {
            TouchFocus focus = items[i];
            if ((focus.listener != exceptListener || focus.listenerActor != exceptActor) && touchFocuses.removeValue(focus, true)) {
                event.setTarget(focus.target);
                event.setListenerActor(focus.listenerActor);
                event.setPointer(focus.pointer);
                event.setButton(focus.button);
                focus.listener.handle(event);
            }
        }
        touchFocuses.end();
        Pools.free(event);
    }

    public void addActor(Actor actor) {
        this.root.addActor(actor);
    }

    public void addAction(Action action) {
        this.root.addAction(action);
    }

    public Array<Actor> getActors() {
        return this.root.children;
    }

    public boolean addListener(EventListener listener) {
        return this.root.addListener(listener);
    }

    public boolean removeListener(EventListener listener) {
        return this.root.removeListener(listener);
    }

    public boolean addCaptureListener(EventListener listener) {
        return this.root.addCaptureListener(listener);
    }

    public boolean removeCaptureListener(EventListener listener) {
        return this.root.removeCaptureListener(listener);
    }

    public void clear() {
        unfocusAll();
        this.root.clear();
    }

    public void unfocusAll() {
        setScrollFocus(null);
        setKeyboardFocus(null);
        cancelTouchFocus();
    }

    public void unfocus(Actor actor) {
        cancelTouchFocus(actor);
        Actor actor2 = this.scrollFocus;
        if (actor2 != null && actor2.isDescendantOf(actor)) {
            setScrollFocus(null);
        }
        Actor actor3 = this.keyboardFocus;
        if (actor3 == null || !actor3.isDescendantOf(actor)) {
            return;
        }
        setKeyboardFocus(null);
    }

    public boolean setKeyboardFocus(Actor actor) {
        if (this.keyboardFocus == actor) {
            return true;
        }
        FocusListener.FocusEvent event = (FocusListener.FocusEvent) Pools.obtain(FocusListener.FocusEvent.class);
        event.setStage(this);
        event.setType(FocusListener.FocusEvent.Type.keyboard);
        Actor oldKeyboardFocus = this.keyboardFocus;
        if (oldKeyboardFocus != null) {
            event.setFocused(false);
            event.setRelatedActor(actor);
            oldKeyboardFocus.fire(event);
        }
        boolean success = !event.isCancelled();
        if (success) {
            this.keyboardFocus = actor;
            if (actor != null) {
                event.setFocused(true);
                event.setRelatedActor(oldKeyboardFocus);
                actor.fire(event);
                success = true ^ event.isCancelled();
                if (!success) {
                    this.keyboardFocus = oldKeyboardFocus;
                }
            }
        }
        Pools.free(event);
        return success;
    }

    public Actor getKeyboardFocus() {
        return this.keyboardFocus;
    }

    public boolean setScrollFocus(Actor actor) {
        if (this.scrollFocus == actor) {
            return true;
        }
        FocusListener.FocusEvent event = (FocusListener.FocusEvent) Pools.obtain(FocusListener.FocusEvent.class);
        event.setStage(this);
        event.setType(FocusListener.FocusEvent.Type.scroll);
        Actor oldScrollFocus = this.scrollFocus;
        if (oldScrollFocus != null) {
            event.setFocused(false);
            event.setRelatedActor(actor);
            oldScrollFocus.fire(event);
        }
        boolean success = !event.isCancelled();
        if (success) {
            this.scrollFocus = actor;
            if (actor != null) {
                event.setFocused(true);
                event.setRelatedActor(oldScrollFocus);
                actor.fire(event);
                success = true ^ event.isCancelled();
                if (!success) {
                    this.scrollFocus = oldScrollFocus;
                }
            }
        }
        Pools.free(event);
        return success;
    }

    public Actor getScrollFocus() {
        return this.scrollFocus;
    }

    public Batch getBatch() {
        return this.batch;
    }

    public Viewport getViewport() {
        return this.viewport;
    }

    public void setViewport(Viewport viewport) {
        this.viewport = viewport;
    }

    public float getWidth() {
        return this.viewport.getWorldWidth();
    }

    public float getHeight() {
        return this.viewport.getWorldHeight();
    }

    public Camera getCamera() {
        return this.viewport.getCamera();
    }

    public Group getRoot() {
        return this.root;
    }

    public void setRoot(Group root) {
        if (root.parent != null) {
            root.parent.removeActor(root, false);
        }
        this.root = root;
        root.setParent(null);
        root.setStage(this);
    }

    public Actor hit(float stageX, float stageY, boolean touchable) {
        this.root.parentToLocalCoordinates(this.tempCoords.set(stageX, stageY));
        return this.root.hit(this.tempCoords.x, this.tempCoords.y, touchable);
    }

    public Vector2 screenToStageCoordinates(Vector2 screenCoords) {
        this.viewport.unproject(screenCoords);
        return screenCoords;
    }

    public Vector2 stageToScreenCoordinates(Vector2 stageCoords) {
        this.viewport.project(stageCoords);
        stageCoords.y = Gdx.graphics.getHeight() - stageCoords.y;
        return stageCoords;
    }

    public Vector2 toScreenCoordinates(Vector2 coords, Matrix4 transformMatrix) {
        return this.viewport.toScreenCoordinates(coords, transformMatrix);
    }

    public void calculateScissors(Rectangle localRect, Rectangle scissorRect) {
        Matrix4 transformMatrix;
        ShapeRenderer shapeRenderer = this.debugShapes;
        if (shapeRenderer != null && shapeRenderer.isDrawing()) {
            transformMatrix = this.debugShapes.getTransformMatrix();
        } else {
            transformMatrix = this.batch.getTransformMatrix();
        }
        this.viewport.calculateScissors(transformMatrix, localRect, scissorRect);
    }

    public void setActionsRequestRendering(boolean actionsRequestRendering) {
        this.actionsRequestRendering = actionsRequestRendering;
    }

    public boolean getActionsRequestRendering() {
        return this.actionsRequestRendering;
    }

    public Color getDebugColor() {
        return this.debugColor;
    }

    public void setDebugInvisible(boolean debugInvisible) {
        this.debugInvisible = debugInvisible;
    }

    public void setDebugAll(boolean debugAll) {
        if (this.debugAll == debugAll) {
            return;
        }
        this.debugAll = debugAll;
        if (!debugAll) {
            this.root.setDebug(false, true);
        } else {
            debug = true;
        }
    }

    public boolean isDebugAll() {
        return this.debugAll;
    }

    public void setDebugUnderMouse(boolean debugUnderMouse) {
        if (this.debugUnderMouse == debugUnderMouse) {
            return;
        }
        this.debugUnderMouse = debugUnderMouse;
        if (!debugUnderMouse) {
            this.root.setDebug(false, true);
        } else {
            debug = true;
        }
    }

    public void setDebugParentUnderMouse(boolean debugParentUnderMouse) {
        if (this.debugParentUnderMouse == debugParentUnderMouse) {
            return;
        }
        this.debugParentUnderMouse = debugParentUnderMouse;
        if (!debugParentUnderMouse) {
            this.root.setDebug(false, true);
        } else {
            debug = true;
        }
    }

    public void setDebugTableUnderMouse(Table.Debug debugTableUnderMouse) {
        if (debugTableUnderMouse == null) {
            debugTableUnderMouse = Table.Debug.none;
        }
        if (this.debugTableUnderMouse == debugTableUnderMouse) {
            return;
        }
        this.debugTableUnderMouse = debugTableUnderMouse;
        if (debugTableUnderMouse != Table.Debug.none) {
            debug = true;
        } else {
            this.root.setDebug(false, true);
        }
    }

    public void setDebugTableUnderMouse(boolean debugTableUnderMouse) {
        setDebugTableUnderMouse(debugTableUnderMouse ? Table.Debug.all : Table.Debug.none);
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        clear();
        if (this.ownsBatch) {
            this.batch.dispose();
        }
        ShapeRenderer shapeRenderer = this.debugShapes;
        if (shapeRenderer != null) {
            shapeRenderer.dispose();
        }
    }

    protected boolean isInsideViewport(int screenX, int screenY) {
        int x0 = this.viewport.getScreenX();
        int x1 = this.viewport.getScreenWidth() + x0;
        int y0 = this.viewport.getScreenY();
        int y1 = this.viewport.getScreenHeight() + y0;
        int screenY2 = (Gdx.graphics.getHeight() - 1) - screenY;
        return screenX >= x0 && screenX < x1 && screenY2 >= y0 && screenY2 < y1;
    }

    /* loaded from: classes.dex */
    public static final class TouchFocus implements Pool.Poolable {
        int button;
        EventListener listener;
        Actor listenerActor;
        int pointer;
        Actor target;

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.listenerActor = null;
            this.listener = null;
            this.target = null;
        }
    }
}