package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisScrollPane extends ScrollPane {
    public VisScrollPane(Actor widget, ScrollPane.ScrollPaneStyle style) {
        super(widget, style);
    }

    public VisScrollPane(Actor widget, String styleName) {
        super(widget, VisUI.getSkin(), styleName);
    }

    public VisScrollPane(Actor widget) {
        super(widget, VisUI.getSkin(), "list");
    }
}