package com.badlogic.gdx.scenes.scene2d;

import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public abstract class Action implements Pool.Poolable {
    protected Actor actor;
    private Pool pool;
    protected Actor target;

    public abstract boolean act(float f);

    public void restart() {
    }

    public void setActor(Actor actor) {
        Pool pool;
        this.actor = actor;
        if (this.target == null) {
            setTarget(actor);
        }
        if (actor == null && (pool = this.pool) != null) {
            pool.free(this);
            this.pool = null;
        }
    }

    public Actor getActor() {
        return this.actor;
    }

    public void setTarget(Actor target) {
        this.target = target;
    }

    public Actor getTarget() {
        return this.target;
    }

    @Override // com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        this.actor = null;
        this.target = null;
        this.pool = null;
        restart();
    }

    public Pool getPool() {
        return this.pool;
    }

    public void setPool(Pool pool) {
        this.pool = pool;
    }

    public String toString() {
        String name = getClass().getName();
        int dotIndex = name.lastIndexOf(46);
        if (dotIndex != -1) {
            name = name.substring(dotIndex + 1);
        }
        return name.endsWith("Action") ? name.substring(0, name.length() - 6) : name;
    }
}