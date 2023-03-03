package com.kotcrab.vis.ui.util.value;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;

/* loaded from: classes.dex */
public class PrefHeightIfVisibleValue extends Value {
    public static final PrefHeightIfVisibleValue INSTANCE = new PrefHeightIfVisibleValue();

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
    public float get(Actor actor) {
        if (actor instanceof Widget) {
            Widget widget = (Widget) actor;
            if (widget.isVisible()) {
                return widget.getPrefHeight();
            }
            return 0.0f;
        } else if (actor instanceof Table) {
            Table table = (Table) actor;
            if (table.isVisible()) {
                return table.getPrefHeight();
            }
            return 0.0f;
        } else {
            throw new IllegalStateException("Unsupported actor type for PrefHeightIfVisibleValue: " + actor.getClass());
        }
    }
}