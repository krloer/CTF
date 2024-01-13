package com.kotcrab.vis.ui.util.value;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Value;

/* loaded from: classes.dex */
public class VisValue extends Value {
    private ValueGetter getter;

    /* loaded from: classes.dex */
    public interface ValueGetter {
        float get(Actor actor);
    }

    public VisValue(ValueGetter getter) {
        this.getter = getter;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
    public float get(Actor context) {
        return this.getter.get(context);
    }
}