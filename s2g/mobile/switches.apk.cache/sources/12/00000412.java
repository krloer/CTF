package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;

/* loaded from: classes.dex */
public class DragListener extends InputListener {
    private int button;
    private float dragLastX;
    private float dragLastY;
    private float dragStartX;
    private float dragStartY;
    private float dragX;
    private float dragY;
    private boolean dragging;
    private float tapSquareSize = 14.0f;
    private float touchDownX = -1.0f;
    private float touchDownY = -1.0f;
    private float stageTouchDownX = -1.0f;
    private float stageTouchDownY = -1.0f;
    private int pressedPointer = -1;

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
        int i;
        if (this.pressedPointer != -1) {
            return false;
        }
        if (pointer != 0 || (i = this.button) == -1 || button == i) {
            this.pressedPointer = pointer;
            this.touchDownX = x;
            this.touchDownY = y;
            this.stageTouchDownX = event.getStageX();
            this.stageTouchDownY = event.getStageY();
            return true;
        }
        return false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public void touchDragged(InputEvent event, float x, float y, int pointer) {
        if (pointer != this.pressedPointer) {
            return;
        }
        if (!this.dragging && (Math.abs(this.touchDownX - x) > this.tapSquareSize || Math.abs(this.touchDownY - y) > this.tapSquareSize)) {
            this.dragging = true;
            this.dragStartX = x;
            this.dragStartY = y;
            dragStart(event, x, y, pointer);
            this.dragX = x;
            this.dragY = y;
        }
        if (this.dragging) {
            this.dragLastX = this.dragX;
            this.dragLastY = this.dragY;
            this.dragX = x;
            this.dragY = y;
            drag(event, x, y, pointer);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.InputListener
    public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
        if (pointer == this.pressedPointer) {
            if (this.dragging) {
                dragStop(event, x, y, pointer);
            }
            cancel();
        }
    }

    public void dragStart(InputEvent event, float x, float y, int pointer) {
    }

    public void drag(InputEvent event, float x, float y, int pointer) {
    }

    public void dragStop(InputEvent event, float x, float y, int pointer) {
    }

    public void cancel() {
        this.dragging = false;
        this.pressedPointer = -1;
    }

    public boolean isDragging() {
        return this.dragging;
    }

    public void setTapSquareSize(float halfTapSquareSize) {
        this.tapSquareSize = halfTapSquareSize;
    }

    public float getTapSquareSize() {
        return this.tapSquareSize;
    }

    public float getTouchDownX() {
        return this.touchDownX;
    }

    public float getTouchDownY() {
        return this.touchDownY;
    }

    public float getStageTouchDownX() {
        return this.stageTouchDownX;
    }

    public float getStageTouchDownY() {
        return this.stageTouchDownY;
    }

    public float getDragStartX() {
        return this.dragStartX;
    }

    public void setDragStartX(float dragStartX) {
        this.dragStartX = dragStartX;
    }

    public float getDragStartY() {
        return this.dragStartY;
    }

    public void setDragStartY(float dragStartY) {
        this.dragStartY = dragStartY;
    }

    public float getDragX() {
        return this.dragX;
    }

    public float getDragY() {
        return this.dragY;
    }

    public float getDragDistance() {
        return Vector2.len(this.dragX - this.dragStartX, this.dragY - this.dragStartY);
    }

    public float getDeltaX() {
        return this.dragX - this.dragLastX;
    }

    public float getDeltaY() {
        return this.dragY - this.dragLastY;
    }

    public int getButton() {
        return this.button;
    }

    public void setButton(int button) {
        this.button = button;
    }
}