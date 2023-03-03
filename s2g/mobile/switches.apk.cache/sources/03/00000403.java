package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.input.GestureDetector;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Event;
import com.badlogic.gdx.scenes.scene2d.EventListener;
import com.badlogic.gdx.scenes.scene2d.InputEvent;

/* loaded from: classes.dex */
public class ActorGestureListener implements EventListener {
    static final Vector2 tmpCoords = new Vector2();
    static final Vector2 tmpCoords2 = new Vector2();
    Actor actor;
    private final GestureDetector detector;
    InputEvent event;
    Actor touchDownTarget;

    public ActorGestureListener() {
        this(20.0f, 0.4f, 1.1f, 2.14748365E9f);
    }

    public ActorGestureListener(float halfTapSquareSize, float tapCountInterval, float longPressDuration, float maxFlingDelay) {
        this.detector = new GestureDetector(halfTapSquareSize, tapCountInterval, longPressDuration, maxFlingDelay, new GestureDetector.GestureAdapter() { // from class: com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener.1
            private final Vector2 initialPointer1 = new Vector2();
            private final Vector2 initialPointer2 = new Vector2();
            private final Vector2 pointer1 = new Vector2();
            private final Vector2 pointer2 = new Vector2();

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean tap(float stageX, float stageY, int count, int button) {
                ActorGestureListener.this.actor.stageToLocalCoordinates(ActorGestureListener.tmpCoords.set(stageX, stageY));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.tap(actorGestureListener.event, ActorGestureListener.tmpCoords.x, ActorGestureListener.tmpCoords.y, count, button);
                return true;
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean longPress(float stageX, float stageY) {
                ActorGestureListener.this.actor.stageToLocalCoordinates(ActorGestureListener.tmpCoords.set(stageX, stageY));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                return actorGestureListener.longPress(actorGestureListener.actor, ActorGestureListener.tmpCoords.x, ActorGestureListener.tmpCoords.y);
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean fling(float velocityX, float velocityY, int button) {
                stageToLocalAmount(ActorGestureListener.tmpCoords.set(velocityX, velocityY));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.fling(actorGestureListener.event, ActorGestureListener.tmpCoords.x, ActorGestureListener.tmpCoords.y, button);
                return true;
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean pan(float stageX, float stageY, float deltaX, float deltaY) {
                stageToLocalAmount(ActorGestureListener.tmpCoords.set(deltaX, deltaY));
                float deltaX2 = ActorGestureListener.tmpCoords.x;
                float deltaY2 = ActorGestureListener.tmpCoords.y;
                ActorGestureListener.this.actor.stageToLocalCoordinates(ActorGestureListener.tmpCoords.set(stageX, stageY));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.pan(actorGestureListener.event, ActorGestureListener.tmpCoords.x, ActorGestureListener.tmpCoords.y, deltaX2, deltaY2);
                return true;
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean panStop(float stageX, float stageY, int pointer, int button) {
                ActorGestureListener.this.actor.stageToLocalCoordinates(ActorGestureListener.tmpCoords.set(stageX, stageY));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.panStop(actorGestureListener.event, ActorGestureListener.tmpCoords.x, ActorGestureListener.tmpCoords.y, pointer, button);
                return true;
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean zoom(float initialDistance, float distance) {
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.zoom(actorGestureListener.event, initialDistance, distance);
                return true;
            }

            @Override // com.badlogic.gdx.input.GestureDetector.GestureAdapter, com.badlogic.gdx.input.GestureDetector.GestureListener
            public boolean pinch(Vector2 stageInitialPointer1, Vector2 stageInitialPointer2, Vector2 stagePointer1, Vector2 stagePointer2) {
                ActorGestureListener.this.actor.stageToLocalCoordinates(this.initialPointer1.set(stageInitialPointer1));
                ActorGestureListener.this.actor.stageToLocalCoordinates(this.initialPointer2.set(stageInitialPointer2));
                ActorGestureListener.this.actor.stageToLocalCoordinates(this.pointer1.set(stagePointer1));
                ActorGestureListener.this.actor.stageToLocalCoordinates(this.pointer2.set(stagePointer2));
                ActorGestureListener actorGestureListener = ActorGestureListener.this;
                actorGestureListener.pinch(actorGestureListener.event, this.initialPointer1, this.initialPointer2, this.pointer1, this.pointer2);
                return true;
            }

            private void stageToLocalAmount(Vector2 amount) {
                ActorGestureListener.this.actor.stageToLocalCoordinates(amount);
                amount.sub(ActorGestureListener.this.actor.stageToLocalCoordinates(ActorGestureListener.tmpCoords2.set(0.0f, 0.0f)));
            }
        });
    }

    @Override // com.badlogic.gdx.scenes.scene2d.EventListener
    public boolean handle(Event e) {
        if (e instanceof InputEvent) {
            InputEvent event = (InputEvent) e;
            int i = AnonymousClass2.$SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type[event.getType().ordinal()];
            if (i == 1) {
                this.actor = event.getListenerActor();
                this.touchDownTarget = event.getTarget();
                this.detector.touchDown(event.getStageX(), event.getStageY(), event.getPointer(), event.getButton());
                this.actor.stageToLocalCoordinates(tmpCoords.set(event.getStageX(), event.getStageY()));
                touchDown(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getButton());
                if (event.getTouchFocus()) {
                    event.getStage().addTouchFocus(this, event.getListenerActor(), event.getTarget(), event.getPointer(), event.getButton());
                }
                return true;
            } else if (i != 2) {
                if (i != 3) {
                    return false;
                }
                this.event = event;
                this.actor = event.getListenerActor();
                this.detector.touchDragged(event.getStageX(), event.getStageY(), event.getPointer());
                return true;
            } else if (event.isTouchFocusCancel()) {
                this.detector.reset();
                return false;
            } else {
                this.event = event;
                this.actor = event.getListenerActor();
                this.detector.touchUp(event.getStageX(), event.getStageY(), event.getPointer(), event.getButton());
                this.actor.stageToLocalCoordinates(tmpCoords.set(event.getStageX(), event.getStageY()));
                touchUp(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getButton());
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.badlogic.gdx.scenes.scene2d.utils.ActorGestureListener$2  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type = new int[InputEvent.Type.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type[InputEvent.Type.touchDown.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type[InputEvent.Type.touchUp.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type[InputEvent.Type.touchDragged.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }

    public void touchDown(InputEvent event, float x, float y, int pointer, int button) {
    }

    public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
    }

    public void tap(InputEvent event, float x, float y, int count, int button) {
    }

    public boolean longPress(Actor actor, float x, float y) {
        return false;
    }

    public void fling(InputEvent event, float velocityX, float velocityY, int button) {
    }

    public void pan(InputEvent event, float x, float y, float deltaX, float deltaY) {
    }

    public void panStop(InputEvent event, float x, float y, int pointer, int button) {
    }

    public void zoom(InputEvent event, float initialDistance, float distance) {
    }

    public void pinch(InputEvent event, Vector2 initialPointer1, Vector2 initialPointer2, Vector2 pointer1, Vector2 pointer2) {
    }

    public GestureDetector getGestureDetector() {
        return this.detector;
    }

    public Actor getTouchDownTarget() {
        return this.touchDownTarget;
    }
}