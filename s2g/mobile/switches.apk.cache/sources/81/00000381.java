package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Action;

/* loaded from: classes.dex */
public class RemoveActorAction extends Action {
    private boolean removed;

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public boolean act(float delta) {
        if (!this.removed) {
            this.removed = true;
            this.target.remove();
        }
        return true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        this.removed = false;
    }
}