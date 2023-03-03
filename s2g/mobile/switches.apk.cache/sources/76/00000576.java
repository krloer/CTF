package com.kotcrab.vis.ui.util.value;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Value;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;

/* loaded from: classes.dex */
public class VisWidgetValue extends Value {
    protected WidgetValueGetter getter;

    /* loaded from: classes.dex */
    public interface WidgetValueGetter {
        float get(Widget widget);
    }

    public VisWidgetValue(WidgetValueGetter getter) {
        this.getter = getter;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Value
    public float get(Actor context) {
        return this.getter.get((Widget) context);
    }
}