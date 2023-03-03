package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.SelectBox;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisSelectBox<T> extends SelectBox<T> {
    public VisSelectBox(SelectBox.SelectBoxStyle style) {
        super(style);
        init();
    }

    public VisSelectBox(String styleName) {
        super(VisUI.getSkin(), styleName);
        init();
    }

    public VisSelectBox() {
        super(VisUI.getSkin());
        init();
    }

    private void init() {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisSelectBox.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                FocusManager.resetFocus(VisSelectBox.this.getStage());
                return false;
            }
        });
    }
}