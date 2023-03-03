package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.Stack;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.BorderOwner;

/* loaded from: classes.dex */
public class VisCheckBox extends TextButton implements Focusable, BorderOwner {
    private Image bgImage;
    private boolean drawBorder;
    private boolean focusBorderEnabled;
    private Stack imageStack;
    private Cell<Stack> imageStackCell;
    private boolean stateInvalid;
    private VisCheckBoxStyle style;
    private Image tickImage;

    public VisCheckBox(String text) {
        this(text, (VisCheckBoxStyle) VisUI.getSkin().get(VisCheckBoxStyle.class));
    }

    public VisCheckBox(String text, boolean checked) {
        this(text, (VisCheckBoxStyle) VisUI.getSkin().get(VisCheckBoxStyle.class));
        setChecked(checked);
    }

    public VisCheckBox(String text, String styleName) {
        this(text, (VisCheckBoxStyle) VisUI.getSkin().get(styleName, VisCheckBoxStyle.class));
    }

    public VisCheckBox(String text, VisCheckBoxStyle style) {
        super(text, style);
        this.focusBorderEnabled = true;
        clearChildren();
        this.bgImage = new Image(style.checkBackground);
        this.tickImage = new Image(style.tick);
        Stack stack = new Stack(this.bgImage, this.tickImage);
        this.imageStack = stack;
        this.imageStackCell = add((VisCheckBox) stack);
        Label label = getLabel();
        add((VisCheckBox) label).padLeft(5.0f);
        label.setAlignment(8);
        setSize(getPrefWidth(), getPrefHeight());
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisCheckBox.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (!VisCheckBox.this.isDisabled()) {
                    FocusManager.switchFocus(VisCheckBox.this.getStage(), VisCheckBox.this);
                    return false;
                }
                return false;
            }
        });
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button
    public VisCheckBoxStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof VisCheckBoxStyle)) {
            throw new IllegalArgumentException("style must be a VisCheckBoxStyle.");
        }
        super.setStyle(style);
        this.style = (VisCheckBoxStyle) style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        this.bgImage.setDrawable(getCheckboxBgImage());
        this.tickImage.setDrawable(getCheckboxTickImage());
        super.draw(batch, parentAlpha);
        if (!isDisabled() && this.stateInvalid && this.style.errorBorder != null) {
            this.style.errorBorder.draw(batch, getX() + this.imageStack.getX(), getY() + this.imageStack.getY(), this.imageStack.getWidth(), this.imageStack.getHeight());
        } else if (this.focusBorderEnabled && this.drawBorder && this.style.focusBorder != null) {
            this.style.focusBorder.draw(batch, getX() + this.imageStack.getX(), getY() + this.imageStack.getY(), this.imageStack.getWidth(), this.imageStack.getHeight());
        }
    }

    protected Drawable getCheckboxBgImage() {
        return isDisabled() ? this.style.checkBackground : isPressed() ? this.style.checkBackgroundDown : isOver() ? this.style.checkBackgroundOver : this.style.checkBackground;
    }

    protected Drawable getCheckboxTickImage() {
        if (isChecked()) {
            return isDisabled() ? this.style.tickDisabled : this.style.tick;
        }
        return null;
    }

    public Image getBackgroundImage() {
        return this.bgImage;
    }

    public Image getTickImage() {
        return this.tickImage;
    }

    public Stack getImageStack() {
        return this.imageStack;
    }

    public Cell<Stack> getImageStackCell() {
        return this.imageStackCell;
    }

    public void setStateInvalid(boolean stateInvalid) {
        this.stateInvalid = stateInvalid;
    }

    public boolean setStateInvalid() {
        return this.stateInvalid;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusLost() {
        this.drawBorder = false;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusGained() {
        this.drawBorder = true;
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public boolean isFocusBorderEnabled() {
        return this.focusBorderEnabled;
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public void setFocusBorderEnabled(boolean focusBorderEnabled) {
        this.focusBorderEnabled = focusBorderEnabled;
    }

    /* loaded from: classes.dex */
    public static class VisCheckBoxStyle extends TextButton.TextButtonStyle {
        public Drawable checkBackground;
        public Drawable checkBackgroundDown;
        public Drawable checkBackgroundOver;
        public Drawable errorBorder;
        public Drawable focusBorder;
        public Drawable tick;
        public Drawable tickDisabled;

        public VisCheckBoxStyle() {
        }

        public VisCheckBoxStyle(Drawable checkBackground, Drawable tick, BitmapFont font, Color fontColor) {
            this.checkBackground = checkBackground;
            this.tick = tick;
            this.font = font;
            this.fontColor = fontColor;
        }

        public VisCheckBoxStyle(VisCheckBoxStyle style) {
            super(style);
            this.focusBorder = style.focusBorder;
            this.errorBorder = style.errorBorder;
            this.checkBackground = style.checkBackground;
            this.checkBackgroundOver = style.checkBackgroundOver;
            this.checkBackgroundDown = style.checkBackgroundDown;
            this.tick = style.tick;
            this.tickDisabled = style.tickDisabled;
        }
    }
}