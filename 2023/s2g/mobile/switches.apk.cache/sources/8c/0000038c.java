package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public abstract class TemporalAction extends Action {
    private boolean began;
    private boolean complete;
    private float duration;
    private Interpolation interpolation;
    private boolean reverse;
    private float time;

    protected abstract void update(float f);

    public TemporalAction() {
    }

    public TemporalAction(float duration) {
        this.duration = duration;
    }

    public TemporalAction(float duration, Interpolation interpolation) {
        this.duration = duration;
        this.interpolation = interpolation;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public boolean act(float delta) {
        boolean z = true;
        if (this.complete) {
            return true;
        }
        Pool pool = getPool();
        setPool(null);
        try {
            if (!this.began) {
                begin();
                this.began = true;
            }
            this.time += delta;
            if (this.time < this.duration) {
                z = false;
            }
            this.complete = z;
            float percent = this.complete ? 1.0f : this.time / this.duration;
            if (this.interpolation != null) {
                percent = this.interpolation.apply(percent);
            }
            update(this.reverse ? 1.0f - percent : percent);
            if (this.complete) {
                end();
            }
            return this.complete;
        } finally {
            setPool(pool);
        }
    }

    protected void begin() {
    }

    protected void end() {
    }

    public void finish() {
        this.time = this.duration;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        this.time = 0.0f;
        this.began = false;
        this.complete = false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action, com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        super.reset();
        this.reverse = false;
        this.interpolation = null;
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

    public Interpolation getInterpolation() {
        return this.interpolation;
    }

    public void setInterpolation(Interpolation interpolation) {
        this.interpolation = interpolation;
    }

    public boolean isReverse() {
        return this.reverse;
    }

    public void setReverse(boolean reverse) {
        this.reverse = reverse;
    }

    public boolean isComplete() {
        return this.complete;
    }
}