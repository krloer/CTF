package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;

/* loaded from: classes.dex */
public class ListViewStyle {
    public ScrollPane.ScrollPaneStyle scrollPaneStyle;

    public ListViewStyle() {
    }

    public ListViewStyle(ListViewStyle style) {
        ScrollPane.ScrollPaneStyle scrollPaneStyle = style.scrollPaneStyle;
        if (scrollPaneStyle != null) {
            this.scrollPaneStyle = new ScrollPane.ScrollPaneStyle(scrollPaneStyle);
        }
    }
}