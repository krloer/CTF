package com.kotcrab.vis.ui.util.value;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Value;

/* loaded from: classes.dex */
public class ConstantIfVisibleValue extends Value {
    private Actor actor;
    private float constant;

    public ConstantIfVisibleValue(float constant) {
        this.constant = constant;
    }

    public ConstantIfVisibleValue(Actor actor, float constant) {
        this.actor = actor;
        this.constant = constant;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
    public float get(Actor context) {
        if (this.actor != null) {
            context = this.actor;
        }
        if (context.isVisible()) {
            return this.constant;
        }
        return 0.0f;
    }
}