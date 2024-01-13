package com.badlogic.ashley.systems;

import com.badlogic.ashley.core.EntitySystem;

/* loaded from: classes.dex */
public abstract class IntervalSystem extends EntitySystem {
    private float accumulator;
    private float interval;

    protected abstract void updateInterval();

    public IntervalSystem(float interval) {
        this(interval, 0);
    }

    public IntervalSystem(float interval, int priority) {
        super(priority);
        this.interval = interval;
        this.accumulator = 0.0f;
    }

    public float getInterval() {
        return this.interval;
    }

    @Override // com.badlogic.ashley.core.EntitySystem
    public final void update(float deltaTime) {
        this.accumulator += deltaTime;
        while (true) {
            float f = this.accumulator;
            float f2 = this.interval;
            if (f >= f2) {
                this.accumulator = f - f2;
                updateInterval();
            } else {
                return;
            }
        }
    }
}