package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;

/* loaded from: classes.dex */
public class CheckBox extends TextButton {
    private Image image;
    private Cell imageCell;
    private CheckBoxStyle style;

    public CheckBox(String text, Skin skin) {
        this(text, (CheckBoxStyle) skin.get(CheckBoxStyle.class));
    }

    public CheckBox(String text, Skin skin, String styleName) {
        this(text, (CheckBoxStyle) skin.get(styleName, CheckBoxStyle.class));
    }

    public CheckBox(String text, CheckBoxStyle style) {
        super(text, style);
        clearChildren();
        Label label = getLabel();
        Image image = new Image(style.checkboxOff, Scaling.none);
        this.image = image;
        this.imageCell = add((CheckBox) image);
        add((CheckBox) label);
        label.setAlignment(8);
        setSize(getPrefWidth(), getPrefHeight());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof CheckBoxStyle)) {
            throw new IllegalArgumentException("style must be a CheckBoxStyle.");
        }
        this.style = (CheckBoxStyle) style;
        super.setStyle(style);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button
    public CheckBoxStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.TextButton, com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Drawable checkbox = null;
        if (isDisabled()) {
            if (this.isChecked && this.style.checkboxOnDisabled != null) {
                checkbox = this.style.checkboxOnDisabled;
            } else {
                checkbox = this.style.checkboxOffDisabled;
            }
        }
        if (checkbox == null) {
            boolean over = isOver() && !isDisabled();
            if (this.isChecked && this.style.checkboxOn != null) {
                checkbox = (!over || this.style.checkboxOnOver == null) ? this.style.checkboxOn : this.style.checkboxOnOver;
            } else if (over && this.style.checkboxOver != null) {
                checkbox = this.style.checkboxOver;
            } else {
                checkbox = this.style.checkboxOff;
            }
        }
        this.image.setDrawable(checkbox);
        super.draw(batch, parentAlpha);
    }

    public Image getImage() {
        return this.image;
    }

    public Cell getImageCell() {
        return this.imageCell;
    }

    /* loaded from: classes.dex */
    public static class CheckBoxStyle extends TextButton.TextButtonStyle {
        public Drawable checkboxOff;
        public Drawable checkboxOffDisabled;
        public Drawable checkboxOn;
        public Drawable checkboxOnDisabled;
        public Drawable checkboxOnOver;
        public Drawable checkboxOver;

        public CheckBoxStyle() {
        }

        public CheckBoxStyle(Drawable checkboxOff, Drawable checkboxOn, BitmapFont font, Color fontColor) {
            this.checkboxOff = checkboxOff;
            this.checkboxOn = checkboxOn;
            this.font = font;
            this.fontColor = fontColor;
        }

        public CheckBoxStyle(CheckBoxStyle style) {
            super(style);
            this.checkboxOff = style.checkboxOff;
            this.checkboxOn = style.checkboxOn;
            this.checkboxOnOver = style.checkboxOnOver;
            this.checkboxOver = style.checkboxOver;
            this.checkboxOnDisabled = style.checkboxOnDisabled;
            this.checkboxOffDisabled = style.checkboxOffDisabled;
        }
    }
}