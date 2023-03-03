package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public class SizeToAction extends TemporalAction {
    private float endHeight;
    private float endWidth;
    private float startHeight;
    private float startWidth;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        this.startWidth = this.target.getWidth();
        this.startHeight = this.target.getHeight();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        float width;
        float height;
        if (percent == 0.0f) {
            width = this.startWidth;
            height = this.startHeight;
        } else if (percent == 1.0f) {
            width = this.endWidth;
            height = this.endHeight;
        } else {
            float width2 = this.startWidth;
            width = width2 + ((this.endWidth - width2) * percent);
            float f = this.startHeight;
            height = f + ((this.endHeight - f) * percent);
        }
        this.target.setSize(width, height);
    }

    public void setSize(float width, float height) {
        this.endWidth = width;
        this.endHeight = height;
    }

    public float getWidth() {
        return this.endWidth;
    }

    public void setWidth(float width) {
        this.endWidth = width;
    }

    public float getHeight() {
        return this.endHeight;
    }

    public void setHeight(float height) {
        this.endHeight = height;
    }
}