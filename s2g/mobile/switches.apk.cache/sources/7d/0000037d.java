package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public class MoveToAction extends TemporalAction {
    private int alignment = 12;
    private float endX;
    private float endY;
    private float startX;
    private float startY;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        this.startX = this.target.getX(this.alignment);
        this.startY = this.target.getY(this.alignment);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        float x;
        float y;
        if (percent == 0.0f) {
            x = this.startX;
            y = this.startY;
        } else if (percent == 1.0f) {
            x = this.endX;
            y = this.endY;
        } else {
            float x2 = this.startX;
            x = x2 + ((this.endX - x2) * percent);
            float f = this.startY;
            y = f + ((this.endY - f) * percent);
        }
        this.target.setPosition(x, y, this.alignment);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction, com.badlogic.gdx.scenes.scene2d.Action, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.alignment = 12;
    }

    public void setStartPosition(float x, float y) {
        this.startX = x;
        this.startY = y;
    }

    public void setPosition(float x, float y) {
        this.endX = x;
        this.endY = y;
    }

    public void setPosition(float x, float y, int alignment) {
        this.endX = x;
        this.endY = y;
        this.alignment = alignment;
    }

    public float getX() {
        return this.endX;
    }

    public void setX(float x) {
        this.endX = x;
    }

    public float getY() {
        return this.endY;
    }

    public void setY(float y) {
        this.endY = y;
    }

    public float getStartX() {
        return this.startX;
    }

    public float getStartY() {
        return this.startY;
    }

    public int getAlignment() {
        return this.alignment;
    }

    public void setAlignment(int alignment) {
        this.alignment = alignment;
    }
}