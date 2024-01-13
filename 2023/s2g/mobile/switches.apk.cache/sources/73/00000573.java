package com.kotcrab.vis.ui.util.value;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;

/* loaded from: classes.dex */
public class PrefWidthIfVisibleValue extends Value {
    public static final PrefWidthIfVisibleValue INSTANCE = new PrefWidthIfVisibleValue();

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
    public float get(Actor actor) {
        if (actor instanceof Widget) {
            Widget widget = (Widget) actor;
            if (widget.isVisible()) {
                return widget.getPrefWidth();
            }
            return 0.0f;
        } else if (actor instanceof Table) {
            Table table = (Table) actor;
            if (table.isVisible()) {
                return table.getPrefWidth();
            }
            return 0.0f;
        } else {
            throw new IllegalStateException("Unsupported actor type for PrefWidthIfVisibleValue: " + actor.getClass());
        }
    }
}