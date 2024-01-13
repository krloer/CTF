package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Event;
import com.badlogic.gdx.scenes.scene2d.EventListener;

/* loaded from: classes.dex */
public abstract class FocusListener implements EventListener {
    @Override // com.badlogic.gdx.scenes.scene2d.EventListener
    public boolean handle(Event event) {
        if (event instanceof FocusEvent) {
            FocusEvent focusEvent = (FocusEvent) event;
            int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$scenes$scene2d$utils$FocusListener$FocusEvent$Type[focusEvent.getType().ordinal()];
            if (i == 1) {
                keyboardFocusChanged(focusEvent, event.getTarget(), focusEvent.isFocused());
            } else if (i == 2) {
                scrollFocusChanged(focusEvent, event.getTarget(), focusEvent.isFocused());
            }
            return false;
        }
        return false;
    }

    /* renamed from: com.badlogic.gdx.scenes.scene2d.utils.FocusListener$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$scenes$scene2d$utils$FocusListener$FocusEvent$Type = new int[FocusEvent.Type.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$scenes$scene2d$utils$FocusListener$FocusEvent$Type[FocusEvent.Type.keyboard.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$scenes$scene2d$utils$FocusListener$FocusEvent$Type[FocusEvent.Type.scroll.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    public void keyboardFocusChanged(FocusEvent event, Actor actor, boolean focused) {
    }

    public void scrollFocusChanged(FocusEvent event, Actor actor, boolean focused) {
    }

    /* loaded from: classes.dex */
    public static class FocusEvent extends Event {
        private boolean focused;
        private Actor relatedActor;
        private Type type;

        /* loaded from: classes.dex */
        public enum Type {
            keyboard,
            scroll
        }

        @Override // com.badlogic.gdx.scenes.scene2d.Event, com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            super.reset();
            this.relatedActor = null;
        }

        public boolean isFocused() {
            return this.focused;
        }

        public void setFocused(boolean focused) {
            this.focused = focused;
        }

        public Type getType() {
            return this.type;
        }

        public void setType(Type focusType) {
            this.type = focusType;
        }

        public Actor getRelatedActor() {
            return this.relatedActor;
        }

        public void setRelatedActor(Actor relatedActor) {
            this.relatedActor = relatedActor;
        }
    }
}