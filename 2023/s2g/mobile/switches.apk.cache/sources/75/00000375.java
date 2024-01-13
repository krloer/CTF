package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public class DelayAction extends DelegateAction {
    private float duration;
    private float time;

    public DelayAction() {
    }

    public DelayAction(float duration) {
        this.duration = duration;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.DelegateAction
    protected boolean delegate(float delta) {
        float f = this.time;
        float f2 = this.duration;
        if (f < f2) {
            this.time = f + delta;
            float f3 = this.time;
            if (f3 < f2) {
                return false;
            }
            delta = f3 - f2;
        }
        if (this.action == null) {
            return true;
        }
        return this.action.act(delta);
    }

    public void finish() {
        this.time = this.duration;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.DelegateAction, com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        super.restart();
        this.time = 0.0f;
    }

    public float getTime() {
        return this.time;
    }

    public void setTime(float time) {
        this.time = time;
    }

    public float getDuration() {
        return this.duration;
    }

    public void setDuration(float duration) {
        this.duration = duration;
    }
}