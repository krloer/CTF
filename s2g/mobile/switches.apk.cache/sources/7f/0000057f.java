package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.EventListener;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.Touchable;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.kotcrab.vis.ui.layout.DragPane;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Draggable extends InputListener {
    private float alpha;
    private boolean blockInput;
    private float deadzoneRadius;
    private float dragStartX;
    private float dragStartY;
    private Interpolation fadingInterpolation;
    private float fadingTime;
    private boolean invisibleWhenDragged;
    private boolean keepWithinParent;
    private DragListener listener;
    private final MimicActor mimic;
    private Interpolation movingInterpolation;
    private float movingTime;
    private float offsetX;
    private float offsetY;
    private static final Vector2 MIMIC_COORDINATES = new Vector2();
    private static final Vector2 STAGE_COORDINATES = new Vector2();
    public static float DEFAULT_FADING_TIME = 0.1f;
    public static float DEFAULT_MOVING_TIME = 0.1f;
    public static boolean INVISIBLE_ON_DRAG = false;
    public static boolean KEEP_WITHIN_PARENT = false;
    public static float DEFAULT_ALPHA = 1.0f;
    public static DragListener DEFAULT_LISTENER = new DragPane.DefaultDragListener();
    public static boolean BLOCK_INPUT = true;
    private static final Actor BLOCKER = new Actor();

    /* loaded from: classes.dex */
    public interface DragListener {
        public static final boolean APPROVE = true;
        public static final boolean CANCEL = false;

        void onDrag(Draggable draggable, Actor actor, float f, float f2);

        boolean onEnd(Draggable draggable, Actor actor, float f, float f2);

        boolean onStart(Draggable draggable, Actor actor, float f, float f2);
    }

    static {
        BLOCKER.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.Draggable.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean mouseMoved(InputEvent event, float x, float y) {
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                return true;
            }

            public boolean scrolled(InputEvent event, float x, float y, int amount) {
                return true;
            }
        });
    }

    public Draggable() {
        this(DEFAULT_LISTENER);
    }

    public Draggable(DragListener listener) {
        this.blockInput = BLOCK_INPUT;
        this.invisibleWhenDragged = INVISIBLE_ON_DRAG;
        this.keepWithinParent = KEEP_WITHIN_PARENT;
        float f = DEFAULT_FADING_TIME;
        this.fadingTime = f;
        this.movingTime = f;
        this.alpha = DEFAULT_ALPHA;
        this.fadingInterpolation = Interpolation.fade;
        this.movingInterpolation = Interpolation.sineOut;
        this.mimic = new MimicActor();
        this.listener = listener;
        this.mimic.setTouchable(Touchable.disabled);
    }

    public void attachTo(Actor actor) {
        Iterator<EventListener> listeners = actor.getListeners().iterator();
        while (listeners.hasNext()) {
            EventListener listener = listeners.next();
            if (listener instanceof Draggable) {
                listeners.remove();
            }
        }
        actor.addListener(this);
    }

    public float getOffsetX() {
        return this.offsetX;
    }

    public float getOffsetY() {
        return this.offsetY;
    }

    public float getAlpha() {
        return this.alpha;
    }

    public void setAlpha(float alpha) {
        this.alpha = alpha;
    }

    public boolean isBlockingInput() {
        return this.blockInput;
    }

    public void setBlockInput(boolean blockInput) {
        this.blockInput = blockInput;
    }

    public boolean isInvisibleWhenDragged() {
        return this.invisibleWhenDragged;
    }

    public void setInvisibleWhenDragged(boolean invisibleWhenDragged) {
        this.invisibleWhenDragged = invisibleWhenDragged;
    }

    public boolean isKeptWithinParent() {
        return this.keepWithinParent;
    }

    public void setKeepWithinParent(boolean keepWithinParent) {
        this.keepWithinParent = keepWithinParent;
    }

    public float getDeadzoneRadius() {
        return this.deadzoneRadius;
    }

    public void setDeadzoneRadius(float deadzoneRadius) {
        this.deadzoneRadius = deadzoneRadius;
    }

    public float getFadingTime() {
        return this.fadingTime;
    }

    public void setFadingTime(float fadingTime) {
        this.fadingTime = fadingTime;
    }

    public float getMovingTime() {
        return this.movingTime;
    }

    public void setMovingTime(float movingTime) {
        this.movingTime = movingTime;
    }

    public void setMovingInterpolation(Interpolation movingInterpolation) {
        this.movingInterpolation = movingInterpolation;
    }

    public void setFadingInterpolation(Interpolation fadingInterpolation) {
        this.fadingInterpolation = fadingInterpolation;
    }

    public void setListener(DragListener listener) {
        this.listener = listener;
    }

    public DragListener getListener() {
        return this.listener;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
        Actor actor = event.getListenerActor();
        if (!isValid(actor) || isDisabled(actor)) {
            return false;
        }
        DragListener dragListener = this.listener;
        if (dragListener == null || dragListener.onStart(this, actor, event.getStageX(), event.getStageY())) {
            attachMimic(actor, event, x, y);
            return true;
        }
        return false;
    }

    protected boolean isValid(Actor actor) {
        return (actor == null || actor.getStage() == null) ? false : true;
    }

    protected boolean isDisabled(Actor actor) {
        return (actor instanceof Disableable) && ((Disableable) actor).isDisabled();
    }

    protected void attachMimic(Actor actor, InputEvent event, float x, float y) {
        this.mimic.clearActions();
        this.mimic.getColor().a = this.alpha;
        this.mimic.setActor(actor);
        this.offsetX = -x;
        this.offsetY = -y;
        getStageCoordinates(event);
        this.dragStartX = MIMIC_COORDINATES.x;
        this.dragStartY = MIMIC_COORDINATES.y;
        this.mimic.setPosition(this.dragStartX, this.dragStartY);
        actor.getStage().addActor(this.mimic);
        this.mimic.toFront();
        actor.setVisible(!this.invisibleWhenDragged);
        if (this.blockInput) {
            addBlocker(actor.getStage());
        }
    }

    protected static void addBlocker(Stage stage) {
        stage.addActor(BLOCKER);
        BLOCKER.setBounds(0.0f, 0.0f, stage.getWidth(), stage.getHeight());
        BLOCKER.toFront();
    }

    protected static void removeBlocker() {
        BLOCKER.remove();
    }

    protected void getStageCoordinates(InputEvent event) {
        if (this.keepWithinParent) {
            getStageCoordinatesWithinParent(event);
        } else if (this.deadzoneRadius > 0.0f) {
            getStageCoordinatesWithDeadzone(event);
        } else {
            getStageCoordinatesWithOffset(event);
        }
    }

    private void getStageCoordinatesWithDeadzone(InputEvent event) {
        Actor parent = this.mimic.getActor().getParent();
        if (parent != null) {
            MIMIC_COORDINATES.set(Vector2.Zero);
            parent.localToStageCoordinates(MIMIC_COORDINATES);
            float parentX = MIMIC_COORDINATES.x;
            float parentY = MIMIC_COORDINATES.y;
            float parentEndX = parentX + parent.getWidth();
            float parentEndY = parentY + parent.getHeight();
            if (isWithinDeadzone(event, parentX, parentY, parentEndX, parentEndY)) {
                MIMIC_COORDINATES.set(event.getStageX() + this.offsetX, event.getStageY() + this.offsetY);
                if (MIMIC_COORDINATES.x < parentX) {
                    MIMIC_COORDINATES.x = parentX;
                } else if (MIMIC_COORDINATES.x + this.mimic.getWidth() > parentEndX) {
                    MIMIC_COORDINATES.x = parentEndX - this.mimic.getWidth();
                }
                if (MIMIC_COORDINATES.y < parentY) {
                    MIMIC_COORDINATES.y = parentY;
                } else if (MIMIC_COORDINATES.y + this.mimic.getHeight() > parentEndY) {
                    MIMIC_COORDINATES.y = parentEndY - this.mimic.getHeight();
                }
                STAGE_COORDINATES.set(MathUtils.clamp(event.getStageX(), parentX, parentEndX - 1.0f), MathUtils.clamp(event.getStageY(), parentY, parentEndY - 1.0f));
                return;
            }
            getStageCoordinatesWithOffset(event);
            return;
        }
        getStageCoordinatesWithOffset(event);
    }

    private boolean isWithinDeadzone(InputEvent event, float parentX, float parentY, float parentEndX, float parentEndY) {
        return parentX - this.deadzoneRadius <= event.getStageX() && this.deadzoneRadius + parentEndX >= event.getStageX() && parentY - this.deadzoneRadius <= event.getStageY() && this.deadzoneRadius + parentEndY >= event.getStageY();
    }

    private void getStageCoordinatesWithinParent(InputEvent event) {
        Actor parent = this.mimic.getActor().getParent();
        if (parent != null) {
            MIMIC_COORDINATES.set(Vector2.Zero);
            parent.localToStageCoordinates(MIMIC_COORDINATES);
            float parentX = MIMIC_COORDINATES.x;
            float parentY = MIMIC_COORDINATES.y;
            float parentEndX = parent.getWidth() + parentX;
            float parentEndY = parent.getHeight() + parentY;
            MIMIC_COORDINATES.set(event.getStageX() + this.offsetX, event.getStageY() + this.offsetY);
            if (MIMIC_COORDINATES.x < parentX) {
                MIMIC_COORDINATES.x = parentX;
            } else if (MIMIC_COORDINATES.x + this.mimic.getWidth() > parentEndX) {
                MIMIC_COORDINATES.x = parentEndX - this.mimic.getWidth();
            }
            if (MIMIC_COORDINATES.y < parentY) {
                MIMIC_COORDINATES.y = parentY;
            } else if (MIMIC_COORDINATES.y + this.mimic.getHeight() > parentEndY) {
                MIMIC_COORDINATES.y = parentEndY - this.mimic.getHeight();
            }
            STAGE_COORDINATES.set(MathUtils.clamp(event.getStageX(), parentX, parentEndX - 1.0f), MathUtils.clamp(event.getStageY(), parentY, parentEndY - 1.0f));
            return;
        }
        getStageCoordinatesWithOffset(event);
    }

    private void getStageCoordinatesWithOffset(InputEvent event) {
        MIMIC_COORDINATES.set(event.getStageX() + this.offsetX, event.getStageY() + this.offsetY);
        STAGE_COORDINATES.set(event.getStageX(), event.getStageY());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public void touchDragged(InputEvent event, float x, float y, int pointer) {
        if (isDragged()) {
            getStageCoordinates(event);
            this.mimic.setPosition(MIMIC_COORDINATES.x, MIMIC_COORDINATES.y);
            DragListener dragListener = this.listener;
            if (dragListener != null) {
                dragListener.onDrag(this, this.mimic.getActor(), STAGE_COORDINATES.x, STAGE_COORDINATES.y);
            }
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
        if (isDragged()) {
            removeBlocker();
            getStageCoordinates(event);
            this.mimic.setPosition(MIMIC_COORDINATES.x, MIMIC_COORDINATES.y);
            if (this.listener == null || (this.mimic.getActor().getStage() != null && this.listener.onEnd(this, this.mimic.getActor(), STAGE_COORDINATES.x, STAGE_COORDINATES.y))) {
                addMimicHidingAction(Actions.fadeOut(this.fadingTime, this.fadingInterpolation), this.fadingTime);
            } else {
                addMimicHidingAction(Actions.moveTo(this.dragStartX, this.dragStartY, this.movingTime, this.movingInterpolation), this.movingTime);
            }
        }
    }

    public boolean isDragged() {
        return this.mimic.getActor() != null;
    }

    protected void addMimicHidingAction(Action hidingAction, float delay) {
        this.mimic.addAction(Actions.sequence(hidingAction, Actions.removeActor()));
        this.mimic.getActor().addAction(Actions.delay(delay, Actions.visible(true)));
    }

    /* loaded from: classes.dex */
    public static class DragAdapter implements DragListener {
        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public boolean onStart(Draggable draggable, Actor actor, float stageX, float stageY) {
            return true;
        }

        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public void onDrag(Draggable draggable, Actor actor, float stageX, float stageY) {
        }

        @Override // com.kotcrab.vis.ui.widget.Draggable.DragListener
        public boolean onEnd(Draggable draggable, Actor actor, float stageX, float stageY) {
            return true;
        }
    }

    /* loaded from: classes.dex */
    public static class MimicActor extends Actor {
        private static final Vector2 LAST_POSITION = new Vector2();
        private Actor actor;

        public MimicActor() {
        }

        public MimicActor(Actor actor) {
            this.actor = actor;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Actor
        public boolean remove() {
            this.actor = null;
            return super.remove();
        }

        public Actor getActor() {
            return this.actor;
        }

        public void setActor(Actor actor) {
            this.actor = actor;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Actor
        public float getWidth() {
            Actor actor = this.actor;
            if (actor == null) {
                return 0.0f;
            }
            return actor.getWidth();
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Actor
        public float getHeight() {
            Actor actor = this.actor;
            if (actor == null) {
                return 0.0f;
            }
            return actor.getHeight();
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Actor
        public void draw(Batch batch, float parentAlpha) {
            Actor actor = this.actor;
            if (actor != null) {
                LAST_POSITION.set(actor.getX(), this.actor.getY());
                this.actor.setPosition(getX(), getY());
                this.actor.draw(batch, getColor().a * parentAlpha);
                this.actor.setPosition(LAST_POSITION.x, LAST_POSITION.y);
            }
        }
    }
}