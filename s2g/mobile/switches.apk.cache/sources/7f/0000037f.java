package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public abstract class RelativeTemporalAction extends TemporalAction {
    private float lastPercent;

    protected abstract void updateRelative(float f);

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        this.lastPercent = 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        updateRelative(percent - this.lastPercent);
        this.lastPercent = percent;
    }
}