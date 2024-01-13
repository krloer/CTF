package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class ParallelAction extends Action {
    Array<Action> actions = new Array<>(4);
    private boolean complete;

    public ParallelAction() {
    }

    public ParallelAction(Action action1) {
        addAction(action1);
    }

    public ParallelAction(Action action1, Action action2) {
        addAction(action1);
        addAction(action2);
    }

    public ParallelAction(Action action1, Action action2, Action action3) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
    }

    public ParallelAction(Action action1, Action action2, Action action3, Action action4) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
        addAction(action4);
    }

    public ParallelAction(Action action1, Action action2, Action action3, Action action4, Action action5) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
        addAction(action4);
        addAction(action5);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public boolean act(float delta) {
        if (this.complete) {
            return true;
        }
        this.complete = true;
        Pool pool = getPool();
        setPool(null);
        try {
            Array<Action> actions = this.actions;
            int n = actions.size;
            for (int i = 0; i < n && this.actor != null; i++) {
                Action currentAction = actions.get(i);
                if (currentAction.getActor() != null && !currentAction.act(delta)) {
                    this.complete = false;
                }
                if (this.actor == null) {
                    return true;
                }
            }
            return this.complete;
        } finally {
            setPool(pool);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        this.complete = false;
        Array<Action> actions = this.actions;
        int n = actions.size;
        for (int i = 0; i < n; i++) {
            actions.get(i).restart();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.actions.clear();
    }

    public void addAction(Action action) {
        this.actions.add(action);
        if (this.actor != null) {
            action.setActor(this.actor);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void setActor(Actor actor) {
        Array<Action> actions = this.actions;
        int n = actions.size;
        for (int i = 0; i < n; i++) {
            actions.get(i).setActor(actor);
        }
        super.setActor(actor);
    }

    public Array<Action> getActions() {
        return this.actions;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public String toString() {
        StringBuilder buffer = new StringBuilder(64);
        buffer.append(super.toString());
        buffer.append('(');
        Array<Action> actions = this.actions;
        int n = actions.size;
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                buffer.append(", ");
            }
            buffer.append(actions.get(i));
        }
        buffer.append(')');
        return buffer.toString();
    }
}