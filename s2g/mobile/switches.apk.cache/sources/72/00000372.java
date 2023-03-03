package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.graphics.Color;

/* loaded from: classes.dex */
public class AlphaAction extends TemporalAction {
    private Color color;
    private float end;
    private float start;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        if (this.color == null) {
            this.color = this.target.getColor();
        }
        this.start = this.color.a;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        if (percent == 0.0f) {
            this.color.a = this.start;
        } else if (percent == 1.0f) {
            this.color.a = this.end;
        } else {
            Color color = this.color;
            float f = this.start;
            color.a = f + ((this.end - f) * percent);
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

    public float getAlpha() {
        return this.end;
    }

    public void setAlpha(float alpha) {
        this.end = alpha;
    }
}