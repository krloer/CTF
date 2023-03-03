package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public class InputListener implements EventListener {
    private static final Vector2 tmpCoords = new Vector2();

    @Override // com.badlogic.gdx.scenes.scene2d.EventListener
    public boolean handle(Event e) {
        if (e instanceof InputEvent) {
            InputEvent event = (InputEvent) e;
            int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$scenes$scene2d$InputEvent$Type[event.getType().ordinal()];
            if (i != 1) {
                if (i != 2) {
                    if (i == 3) {
                        return keyTyped(event, event.getCharacter());
                    }
                    event.toCoordinates(event.getListenerActor(), tmpCoords);
                    switch (event.getType()) {
                        case touchDown:
                            boolean handled = touchDown(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getButton());
                            if (handled && event.getTouchFocus()) {
                                event.getStage().addTouchFocus(this, event.getListenerActor(), event.getTarget(), event.getPointer(), event.getButton());
                            }
                            return handled;
                        case touchUp:
                            touchUp(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getButton());
                            return true;
                        case touchDragged:
                            touchDragged(event, tmpCoords.x, tmpCoords.y, event.getPointer());
                            return true;
                        case mouseMoved:
                            return mouseMoved(event, tmpCoords.x, tmpCoords.y);
                        case scrolled:
                            return scrolled(event, tmpCoords.x, tmpCoords.y, event.getScrollAmountX(), event.getScrollAmountY());
                        case enter:
                            enter(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getRelatedActor());
                            return false;
                        case exit:
                            exit(event, tmpCoords.x, tmpCoords.y, event.getPointer(), event.getRelatedActor());
                            return false;
                        default:
                            return false;
                    }
                }
                return keyUp(event, event.getKeyCode());
            }
            return keyDown(event, event.getKeyCode());
        }
        return false;
    }

    public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
        return false;
    }

    public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
    }

    public void touchDragged(InputEvent event, float x, float y, int pointer) {
    }

    public boolean mouseMoved(InputEvent event, float x, float y) {
        return false;
    }

    public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
    }

    public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
    }

    public boolean scrolled(InputEvent event, float x, float y, float amountX, float amountY) {
        return false;
    }

    public boolean keyDown(InputEvent event, int keycode) {
        return false;
    }

    public boolean keyUp(InputEvent event, int keycode) {
        return false;
    }

    public boolean keyTyped(InputEvent event, char character) {
        return false;
    }
}