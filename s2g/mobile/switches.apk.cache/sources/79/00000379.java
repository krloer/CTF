package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.math.Interpolation;

/* loaded from: classes.dex */
public class FloatAction extends TemporalAction {
    private float end;
    private float start;
    private float value;

    public FloatAction() {
        this.start = 0.0f;
        this.end = 1.0f;
    }

    public FloatAction(float start, float end) {
        this.start = start;
        this.end = end;
    }

    public FloatAction(float start, float end, float duration) {
        super(duration);
        this.start = start;
        this.end = end;
    }

    public FloatAction(float start, float end, float duration, Interpolation interpolation) {
        super(duration, interpolation);
        this.start = start;
        this.end = end;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        this.value = this.start;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        if (percent == 0.0f) {
            this.value = this.start;
        } else if (percent == 1.0f) {
            this.value = this.end;
        } else {
            float f = this.start;
            this.value = f + ((this.end - f) * percent);
        }
    }

    public float getValue() {
        return this.value;
    }

    public void setValue(float value) {
        this.value = value;
    }

    public float getStart() {
        return this.start;
    }

    public void setStart(float start) {
        this.start = start;
    }

    public float getEnd() {
        return this.end;
    }

    public void setEnd(float end) {
        this.end = end;
    }
}