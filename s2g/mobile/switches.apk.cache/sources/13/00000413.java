package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.badlogic.gdx.utils.Timer;

/* loaded from: classes.dex */
public class DragScrollListener extends DragListener {
    static final Vector2 tmpCoords = new Vector2();
    float padBottom;
    float padTop;
    private ScrollPane scroll;
    private Timer.Task scrollDown;
    private Timer.Task scrollUp;
    long startTime;
    Interpolation interpolation = Interpolation.exp5In;
    float minSpeed = 15.0f;
    float maxSpeed = 75.0f;
    float tickSecs = 0.05f;
    long rampTime = 1750;

    public DragScrollListener(final ScrollPane scroll) {
        this.scroll = scroll;
        this.scrollUp = new Timer.Task() { // from class: com.badlogic.gdx.scenes.scene2d.utils.DragScrollListener.1
            @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
            public void run() {
                DragScrollListener.this.scroll(scroll.getScrollY() - DragScrollListener.this.getScrollPixels());
            }
        };
        this.scrollDown = new Timer.Task() { // from class: com.badlogic.gdx.scenes.scene2d.utils.DragScrollListener.2
            @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
            public void run() {
                DragScrollListener.this.scroll(scroll.getScrollY() + DragScrollListener.this.getScrollPixels());
            }
        };
    }

    public void setup(float minSpeedPixels, float maxSpeedPixels, float tickSecs, float rampSecs) {
        this.minSpeed = minSpeedPixels;
        this.maxSpeed = maxSpeedPixels;
        this.tickSecs = tickSecs;
        this.rampTime = 1000.0f * rampSecs;
    }

    float getScrollPixels() {
        return this.interpolation.apply(this.minSpeed, this.maxSpeed, Math.min(1.0f, ((float) (System.currentTimeMillis() - this.startTime)) / ((float) this.rampTime)));
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.DragListener
    public void drag(InputEvent event, float x, float y, int pointer) {
        event.getListenerActor().localToActorCoordinates(this.scroll, tmpCoords.set(x, y));
        if (isAbove(tmpCoords.y)) {
            this.scrollDown.cancel();
            if (!this.scrollUp.isScheduled()) {
                this.startTime = System.currentTimeMillis();
                Timer.Task task = this.scrollUp;
                float f = this.tickSecs;
                Timer.schedule(task, f, f);
            }
        } else if (isBelow(tmpCoords.y)) {
            this.scrollUp.cancel();
            if (!this.scrollDown.isScheduled()) {
                this.startTime = System.currentTimeMillis();
                Timer.Task task2 = this.scrollDown;
                float f2 = this.tickSecs;
                Timer.schedule(task2, f2, f2);
            }
        } else {
            this.scrollUp.cancel();
            this.scrollDown.cancel();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.DragListener
    public void dragStop(InputEvent event, float x, float y, int pointer) {
        this.scrollUp.cancel();
        this.scrollDown.cancel();
    }

    protected boolean isAbove(float y) {
        return y >= this.scroll.getHeight() - this.padTop;
    }

    protected boolean isBelow(float y) {
        return y < this.padBottom;
    }

    protected void scroll(float y) {
        this.scroll.setScrollY(y);
    }

    public void setPadding(float padTop, float padBottom) {
        this.padTop = padTop;
        this.padBottom = padBottom;
    }
}