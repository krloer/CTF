package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Event;
import com.badlogic.gdx.scenes.scene2d.EventListener;
import com.badlogic.gdx.utils.reflect.ClassReflection;

/* loaded from: classes.dex */
public abstract class EventAction<T extends Event> extends Action {
    boolean active;
    final Class<? extends T> eventClass;
    private final EventListener listener = new EventListener() { // from class: com.badlogic.gdx.scenes.scene2d.actions.EventAction.1
        @Override // com.badlogic.gdx.scenes.scene2d.EventListener
        public boolean handle(Event event) {
            if (!EventAction.this.active || !ClassReflection.isInstance(EventAction.this.eventClass, event)) {
                return false;
            }
            EventAction eventAction = EventAction.this;
            eventAction.result = eventAction.handle(event);
            return EventAction.this.result;
        }
    };
    boolean result;

    public abstract boolean handle(T t);

    public EventAction(Class<? extends T> eventClass) {
        this.eventClass = eventClass;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void restart() {
        this.result = false;
        this.active = false;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public void setTarget(Actor newTarget) {
        if (this.target != null) {
            this.target.removeListener(this.listener);
        }
        super.setTarget(newTarget);
        if (newTarget != null) {
            newTarget.addListener(this.listener);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Action
    public boolean act(float delta) {
        this.active = true;
        return this.result;
    }

    public boolean isActive() {
        return this.active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}