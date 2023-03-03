package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.List;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisList<T> extends List<T> {
    public VisList() {
        super(VisUI.getSkin());
        init();
    }

    public VisList(String styleName) {
        super(VisUI.getSkin(), styleName);
        init();
    }

    public VisList(List.ListStyle style) {
        super(style);
        init();
    }

    private void init() {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisList.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                FocusManager.resetFocus(VisList.this.getStage());
                return false;
            }
        });
    }
}