package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class SequenceAction extends ParallelAction {
    private int index;

    public SequenceAction() {
    }

    public SequenceAction(Action action1) {
        addAction(action1);
    }

    public SequenceAction(Action action1, Action action2) {
        addAction(action1);
        addAction(action2);
    }

    public SequenceAction(Action action1, Action action2, Action action3) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
    }

    public SequenceAction(Action action1, Action action2, Action action3, Action action4) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
        addAction(action4);
    }

    public SequenceAction(Action action1, Action action2, Action action3, Action action4, Action action5) {
        addAction(action1);
        addAction(action2);
        addAction(action3);
        addAction(action4);
        addAction(action5);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.ParallelAction, com.badlogic.gdx.scenes.scene2d.Action
    public boolean act(float delta) {
        if (this.index >= this.actions.size) {
            return true;
        }
        Pool pool = getPool();
        setPool(null);
        try {
            if (this.actions.get(this.index).act(delta)) {
                if (this.actor == null) {
                    return true;
                }
                this.index++;
                if (this.index >= this.actions.size) {
                    return true;
                }
            }
            return false;
        } finally {
            setPool(pool);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.ParallelAction, com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        super.restart();
        this.index = 0;
    }
}