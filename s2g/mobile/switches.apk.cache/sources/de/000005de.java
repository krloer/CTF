package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.Tree;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisTree extends Tree {
    public VisTree(String styleName) {
        super(VisUI.getSkin(), styleName);
        init();
    }

    public VisTree() {
        super(VisUI.getSkin());
        init();
    }

    public VisTree(Tree.TreeStyle style) {
        super(style);
        init();
    }

    private void init() {
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisTree.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Focusable focusable = FocusManager.getFocusedWidget();
                if (!(focusable instanceof Actor) || !VisTree.this.isAscendantOf((Actor) focusable)) {
                    FocusManager.resetFocus(VisTree.this.getStage());
                    return false;
                }
                return false;
            }
        });
    }
}