package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.utils.Pool;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public abstract class DelegateAction extends Action {
    protected Action action;

    protected abstract boolean delegate(float f);

    public void setAction(Action action) {
        this.action = action;
    }

    public Action getAction() {
        return this.action;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public final boolean act(float delta) {
        Pool pool = getPool();
        setPool(null);
        try {
            return delegate(delta);
        } finally {
            setPool(pool);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        Action action = this.action;
        if (action != null) {
            action.restart();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.action = null;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void setActor(Actor actor) {
        Action action = this.action;
        if (action != null) {
            action.setActor(actor);
        }
        super.setActor(actor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void setTarget(Actor target) {
        Action action = this.action;
        if (action != null) {
            action.setTarget(target);
        }
        super.setTarget(target);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public String toString() {
        String str;
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        if (this.action == null) {
            str = BuildConfig.FLAVOR;
        } else {
            str = "(" + this.action + ")";
        }
        sb.append(str);
        return sb.toString();
    }
}