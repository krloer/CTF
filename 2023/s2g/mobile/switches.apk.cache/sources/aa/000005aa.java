package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.badlogic.gdx.scenes.scene2d.utils.Cullable;
import com.kotcrab.vis.ui.widget.VisTextArea;
import com.kotcrab.vis.ui.widget.VisTextField;

/* loaded from: classes.dex */
public class ScrollableTextArea extends VisTextArea implements Cullable {
    private Rectangle cullingArea;

    public ScrollableTextArea(String text) {
        super(text, "textArea");
    }

    public ScrollableTextArea(String text, String styleName) {
        super(text, styleName);
    }

    public ScrollableTextArea(String text, VisTextField.VisTextFieldStyle style) {
        super(text, style);
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextArea, com.kotcrab.vis.ui.widget.VisTextField
    protected InputListener createInputListener() {
        return new ScrollTextAreaListener();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setParent(Group parent) {
        super.setParent(parent);
        if (parent instanceof ScrollPane) {
            calculateOffsets();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateScrollPosition() {
        if (this.cullingArea == null || !(getParent() instanceof ScrollPane)) {
            return;
        }
        ScrollPane scrollPane = (ScrollPane) getParent();
        if (!this.cullingArea.contains(getCursorX(), this.cullingArea.y)) {
            scrollPane.setScrollPercentX(getCursorX() / getWidth());
        }
        Rectangle rectangle = this.cullingArea;
        if (!rectangle.contains(rectangle.x, getHeight() - getCursorY())) {
            scrollPane.setScrollPercentY(getCursorY() / getHeight());
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Cullable
    public void setCullingArea(Rectangle cullingArea) {
        this.cullingArea = cullingArea;
    }

    public ScrollPane createCompatibleScrollPane() {
        VisScrollPane scrollPane = new VisScrollPane(this);
        scrollPane.setOverscroll(false, false);
        scrollPane.setFlickScroll(false);
        scrollPane.setFadeScrollBars(false);
        scrollPane.setScrollbarsOnTop(true);
        scrollPane.setScrollingDisabled(true, false);
        return scrollPane;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextArea, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    protected void sizeChanged() {
        super.sizeChanged();
        this.linesShowing = 1000000000;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextArea, com.kotcrab.vis.ui.widget.VisTextField, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        return getLines() * this.style.font.getLineHeight();
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void setText(String str) {
        super.setText(str);
        if (!this.programmaticChangeEvents) {
            updateScrollLayout();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public boolean changeText(String oldText, String newText) {
        boolean changed = super.changeText(oldText, newText);
        updateScrollLayout();
        return changed;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateScrollLayout() {
        invalidateHierarchy();
        layout();
        if (getParent() instanceof ScrollPane) {
            ((ScrollPane) getParent()).layout();
        }
        updateScrollPosition();
    }

    /* loaded from: classes.dex */
    public class ScrollTextAreaListener extends VisTextArea.TextAreaListener {
        public ScrollTextAreaListener() {
            super();
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextArea.TextAreaListener, com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyDown(InputEvent event, int keycode) {
            ScrollableTextArea.this.updateScrollPosition();
            return super.keyDown(event, keycode);
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextArea.TextAreaListener, com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyTyped(InputEvent event, char character) {
            ScrollableTextArea.this.updateScrollPosition();
            return super.keyTyped(event, character);
        }
    }
}