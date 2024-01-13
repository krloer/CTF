package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.math.Vector2;

/* loaded from: classes.dex */
public class InputEvent extends Event {
    private int button;
    private char character;
    private int keyCode;
    private int pointer;
    private Actor relatedActor;
    private float scrollAmountX;
    private float scrollAmountY;
    private float stageX;
    private float stageY;
    private boolean touchFocus = true;
    private Type type;

    /* loaded from: classes.dex */
    public enum Type {
        touchDown,
        touchUp,
        touchDragged,
        mouseMoved,
        enter,
        exit,
        scrolled,
        keyDown,
        keyUp,
        keyTyped
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Event, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.relatedActor = null;
        this.button = -1;
    }

    public float getStageX() {
        return this.stageX;
    }

    public void setStageX(float stageX) {
        this.stageX = stageX;
    }

    public float getStageY() {
        return this.stageY;
    }

    public void setStageY(float stageY) {
        this.stageY = stageY;
    }

    public Type getType() {
        return this.type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public int getPointer() {
        return this.pointer;
    }

    public void setPointer(int pointer) {
        this.pointer = pointer;
    }

    public int getButton() {
        return this.button;
    }

    public void setButton(int button) {
        this.button = button;
    }

    public int getKeyCode() {
        return this.keyCode;
    }

    public void setKeyCode(int keyCode) {
        this.keyCode = keyCode;
    }

    public char getCharacter() {
        return this.character;
    }

    public void setCharacter(char character) {
        this.character = character;
    }

    public float getScrollAmountX() {
        return this.scrollAmountX;
    }

    public float getScrollAmountY() {
        return this.scrollAmountY;
    }

    public void setScrollAmountX(float scrollAmount) {
        this.scrollAmountX = scrollAmount;
    }

    public void setScrollAmountY(float scrollAmount) {
        this.scrollAmountY = scrollAmount;
    }

    public Actor getRelatedActor() {
        return this.relatedActor;
    }

    public void setRelatedActor(Actor relatedActor) {
        this.relatedActor = relatedActor;
    }

    public Vector2 toCoordinates(Actor actor, Vector2 actorCoords) {
        actorCoords.set(this.stageX, this.stageY);
        actor.stageToLocalCoordinates(actorCoords);
        return actorCoords;
    }

    public boolean isTouchFocusCancel() {
        return this.stageX == -2.14748365E9f || this.stageY == -2.14748365E9f;
    }

    public boolean getTouchFocus() {
        return this.touchFocus;
    }

    public void setTouchFocus(boolean touchFocus) {
        this.touchFocus = touchFocus;
    }

    public String toString() {
        return this.type.toString();
    }
}