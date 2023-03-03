package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.math.Interpolation;

/* loaded from: classes.dex */
public class IntAction extends TemporalAction {
    private int end;
    private int start;
    private int value;

    public IntAction() {
        this.start = 0;
        this.end = 1;
    }

    public IntAction(int start, int end) {
        this.start = start;
        this.end = end;
    }

    public IntAction(int start, int end, float duration) {
        super(duration);
        this.start = start;
        this.end = end;
    }

    public IntAction(int start, int end, float duration, Interpolation interpolation) {
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
            int i = this.start;
            this.value = (int) (i + ((this.end - i) * percent));
        }
    }

    public int getValue() {
        return this.value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    public int getStart() {
        return this.start;
    }

    public void setStart(int start) {
        this.start = start;
    }

    public int getEnd() {
        return this.end;
    }

    public void setEnd(int end) {
        this.end = end;
    }
}