package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public class TimeScaleAction extends DelegateAction {
    private float scale;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.DelegateAction
    protected boolean delegate(float delta) {
        if (this.action == null) {
            return true;
        }
        return this.action.act(this.scale * delta);
    }

    public float getScale() {
        return this.scale;
    }

    public void setScale(float scale) {
        this.scale = scale;
    }
}