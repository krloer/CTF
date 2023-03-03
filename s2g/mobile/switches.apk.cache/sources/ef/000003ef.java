package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Input;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.utils.Layout;

/* loaded from: classes.dex */
public abstract class Value {
    public static final Fixed zero = new Fixed(0.0f);
    public static Value minWidth = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.1
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getMinWidth();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getWidth();
        }
    };
    public static Value minHeight = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.2
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getMinHeight();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getHeight();
        }
    };
    public static Value prefWidth = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.3
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getPrefWidth();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getWidth();
        }
    };
    public static Value prefHeight = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.4
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getPrefHeight();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getHeight();
        }
    };
    public static Value maxWidth = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.5
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getMaxWidth();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getWidth();
        }
    };
    public static Value maxHeight = new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.6
        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            if (context instanceof Layout) {
                return ((Layout) context).getMaxHeight();
            }
            if (context == null) {
                return 0.0f;
            }
            return context.getHeight();
        }
    };

    public abstract float get(Actor actor);

    public float get() {
        return get(null);
    }

    /* loaded from: classes.dex */
    public static class Fixed extends Value {
        static final Fixed[] cache = new Fixed[Input.Keys.ESCAPE];
        private final float value;

        public Fixed(float value) {
            this.value = value;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
        public float get(Actor context) {
            return this.value;
        }

        public String toString() {
            return Float.toString(this.value);
        }

        public static Fixed valueOf(float value) {
            if (value == 0.0f) {
                return zero;
            }
            if (value >= -10.0f && value <= 100.0f && value == ((int) value)) {
                Fixed[] fixedArr = cache;
                Fixed fixed = fixedArr[((int) value) + 10];
                if (fixed == null) {
                    Fixed fixed2 = new Fixed(value);
                    fixedArr[((int) value) + 10] = fixed2;
                    return fixed2;
                }
                return fixed;
            }
            return new Fixed(value);
        }
    }

    public static Value percentWidth(final float percent) {
        return new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.7
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
            public float get(Actor actor) {
                return actor.getWidth() * percent;
            }
        };
    }

    public static Value percentHeight(final float percent) {
        return new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.8
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
            public float get(Actor actor) {
                return actor.getHeight() * percent;
            }
        };
    }

    public static Value percentWidth(final float percent, final Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        return new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.9
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
            public float get(Actor context) {
                return Actor.this.getWidth() * percent;
            }
        };
    }

    public static Value percentHeight(final float percent, final Actor actor) {
        if (actor == null) {
            throw new IllegalArgumentException("actor cannot be null.");
        }
        return new Value() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Value.10
            @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
            public float get(Actor context) {
                return Actor.this.getHeight() * percent;
            }
        };
    }
}