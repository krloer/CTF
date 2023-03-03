package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Event;

/* loaded from: classes.dex */
public class CountdownEventAction<T extends Event> extends EventAction<T> {
    int count;
    int current;

    public CountdownEventAction(Class<? extends T> eventClass, int count) {
        super(eventClass);
        this.count = count;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.EventAction
    public boolean handle(T event) {
        this.current++;
        return this.current >= this.count;
    }
}