package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.BorderOwner;

/* loaded from: classes.dex */
public class VisTextButton extends TextButton implements Focusable, BorderOwner {
    private boolean drawBorder;
    private boolean focusBorderEnabled;
    private VisTextButtonStyle style;

    public VisTextButton(String text, String styleName) {
        super(text, (TextButton.TextButtonStyle) VisUI.getSkin().get(styleName, VisTextButtonStyle.class));
        this.focusBorderEnabled = true;
        init();
    }

    public VisTextButton(String text) {
        super(text, (TextButton.TextButtonStyle) VisUI.getSkin().get(VisTextButtonStyle.class));
        this.focusBorderEnabled = true;
        init();
    }

    public VisTextButton(String text, ChangeListener listener) {
        super(text, (TextButton.TextButtonStyle) VisUI.getSkin().get(VisTextButtonStyle.class));
        this.focusBorderEnabled = true;
        init();
        addListener(listener);
    }

    public VisTextButton(String text, String styleName, ChangeListener listener) {
        super(text, (TextButton.TextButtonStyle) VisUI.getSkin().get(styleName, VisTextButtonStyle.class));
        this.focusBorderEnabled = true;
        init();
        addListener(listener);
    }

    public VisTextButton(String text, VisTextButtonStyle buttonStyle) {
        super(text, buttonStyle);
        this.focusBorderEnabled = true;
        init();
    }

    private void init() {
        this.style = (VisTextButtonStyle) getStyle();
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisTextButton.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (!VisTextButton.this.isDisabled()) {
                    FocusManager.switchFocus(VisTextButton.this.getStage(), VisTextButton.this);
                    return false;
                }
                return false;
            }
        });
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        if (this.focusBorderEnabled && this.drawBorder && this.style.focusBorder != null) {
            this.style.focusBorder.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
    }

    /* loaded from: classes.dex */
    public static class VisTextButtonStyle extends TextButton.TextButtonStyle {
        public Drawable focusBorder;

        public VisTextButtonStyle() {
        }

        public VisTextButtonStyle(Drawable up, Drawable down, Drawable checked, BitmapFont font) {
            super(up, down, checked, font);
        }

        public VisTextButtonStyle(VisTextButtonStyle style) {
            super(style);
            this.focusBorder = style.focusBorder;
        }
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public boolean isFocusBorderEnabled() {
        return this.focusBorderEnabled;
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public void setFocusBorderEnabled(boolean focusBorderEnabled) {
        this.focusBorderEnabled = focusBorderEnabled;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusLost() {
        this.drawBorder = false;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusGained() {
        this.drawBorder = true;
    }
}