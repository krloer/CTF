package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.graphics.Color;

/* loaded from: classes.dex */
public class ColorAction extends TemporalAction {
    private Color color;
    private final Color end = new Color();
    private float startA;
    private float startB;
    private float startG;
    private float startR;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        if (this.color == null) {
            this.color = this.target.getColor();
        }
        this.startR = this.color.r;
        this.startG = this.color.g;
        this.startB = this.color.b;
        this.startA = this.color.a;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        if (percent == 0.0f) {
            this.color.set(this.startR, this.startG, this.startB, this.startA);
        } else if (percent == 1.0f) {
            this.color.set(this.end);
        } else {
            float r = this.startR + ((this.end.r - this.startR) * percent);
            float g = this.startG + ((this.end.g - this.startG) * percent);
            float b = this.startB + ((this.end.b - this.startB) * percent);
            float a = this.startA + ((this.end.a - this.startA) * percent);
            this.color.set(r, g, b, a);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction, com.badlogic.gdx.scenes.scene2d.Action, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.color = null;
    }

    public Color getColor() {
        return this.color;
    }

    public void setColor(Color color) {
        this.color = color;
    }

    public Color getEndColor() {
        return this.end;
    }

    public void setEndColor(Color color) {
        this.end.set(color);
    }
}