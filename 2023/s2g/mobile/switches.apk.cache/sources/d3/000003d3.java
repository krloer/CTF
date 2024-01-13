package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class TextButton extends Button {
    private Label label;
    private TextButtonStyle style;

    public TextButton(String text, Skin skin) {
        this(text, (TextButtonStyle) skin.get(TextButtonStyle.class));
        setSkin(skin);
    }

    public TextButton(String text, Skin skin, String styleName) {
        this(text, (TextButtonStyle) skin.get(styleName, TextButtonStyle.class));
        setSkin(skin);
    }

    public TextButton(String text, TextButtonStyle style) {
        setStyle(style);
        this.label = new Label(text, new Label.LabelStyle(style.font, style.fontColor));
        this.label.setAlignment(1);
        add((TextButton) this.label).expand().fill();
        setSize(getPrefWidth(), getPrefHeight());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (style == null) {
            throw new NullPointerException("style cannot be null");
        }
        if (!(style instanceof TextButtonStyle)) {
            throw new IllegalArgumentException("style must be a TextButtonStyle.");
        }
        this.style = (TextButtonStyle) style;
        super.setStyle(style);
        Label label = this.label;
        if (label != null) {
            TextButtonStyle textButtonStyle = (TextButtonStyle) style;
            Label.LabelStyle labelStyle = label.getStyle();
            labelStyle.font = textButtonStyle.font;
            labelStyle.fontColor = textButtonStyle.fontColor;
            this.label.setStyle(labelStyle);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public TextButtonStyle getStyle() {
        return this.style;
    }

    protected Color getFontColor() {
        if (!isDisabled() || this.style.disabledFontColor == null) {
            if (isPressed()) {
                if (isChecked() && this.style.checkedDownFontColor != null) {
                    return this.style.checkedDownFontColor;
                }
                if (this.style.downFontColor != null) {
                    return this.style.downFontColor;
                }
            }
            if (isOver()) {
                if (isChecked()) {
                    if (this.style.checkedOverFontColor != null) {
                        return this.style.checkedOverFontColor;
                    }
                } else if (this.style.overFontColor != null) {
                    return this.style.overFontColor;
                }
            }
            boolean focused = hasKeyboardFocus();
            if (isChecked()) {
                if (focused && this.style.checkedFocusedFontColor != null) {
                    return this.style.checkedFocusedFontColor;
                }
                if (this.style.checkedFontColor != null) {
                    return this.style.checkedFontColor;
                }
                if (isOver() && this.style.overFontColor != null) {
                    return this.style.overFontColor;
                }
            }
            return (!focused || this.style.focusedFontColor == null) ? this.style.fontColor : this.style.focusedFontColor;
        }
        return this.style.disabledFontColor;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        this.label.getStyle().fontColor = getFontColor();
        super.draw(batch, parentAlpha);
    }

    public void setLabel(Label label) {
        if (label == null) {
            throw new IllegalArgumentException("label cannot be null.");
        }
        getLabelCell().setActor(label);
        this.label = label;
    }

    public Label getLabel() {
        return this.label;
    }

    public Cell<Label> getLabelCell() {
        return getCell(this.label);
    }

    public void setText(String text) {
        this.label.setText(text);
    }

    public CharSequence getText() {
        return this.label.getText();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public String toString() {
        String name = getName();
        if (name != null) {
            return name;
        }
        String className = getClass().getName();
        int dotIndex = className.lastIndexOf(46);
        if (dotIndex != -1) {
            className = className.substring(dotIndex + 1);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(className.indexOf(36) != -1 ? "TextButton " : BuildConfig.FLAVOR);
        sb.append(className);
        sb.append(": ");
        sb.append((Object) this.label.getText());
        return sb.toString();
    }

    /* loaded from: classes.dex */
    public static class TextButtonStyle extends Button.ButtonStyle {
        public Color checkedDownFontColor;
        public Color checkedFocusedFontColor;
        public Color checkedFontColor;
        public Color checkedOverFontColor;
        public Color disabledFontColor;
        public Color downFontColor;
        public Color focusedFontColor;
        public BitmapFont font;
        public Color fontColor;
        public Color overFontColor;

        public TextButtonStyle() {
        }

        public TextButtonStyle(Drawable up, Drawable down, Drawable checked, BitmapFont font) {
            super(up, down, checked);
            this.font = font;
        }

        public TextButtonStyle(TextButtonStyle style) {
            super(style);
            this.font = style.font;
            Color color = style.fontColor;
            if (color != null) {
                this.fontColor = new Color(color);
            }
            Color color2 = style.downFontColor;
            if (color2 != null) {
                this.downFontColor = new Color(color2);
            }
            Color color3 = style.overFontColor;
            if (color3 != null) {
                this.overFontColor = new Color(color3);
            }
            Color color4 = style.focusedFontColor;
            if (color4 != null) {
                this.focusedFontColor = new Color(color4);
            }
            Color color5 = style.disabledFontColor;
            if (color5 != null) {
                this.disabledFontColor = new Color(color5);
            }
            Color color6 = style.checkedFontColor;
            if (color6 != null) {
                this.checkedFontColor = new Color(color6);
            }
            Color color7 = style.checkedDownFontColor;
            if (color7 != null) {
                this.checkedDownFontColor = new Color(color7);
            }
            Color color8 = style.checkedOverFontColor;
            if (color8 != null) {
                this.checkedOverFontColor = new Color(color8);
            }
            Color color9 = style.checkedFocusedFontColor;
            if (color9 != null) {
                this.checkedFocusedFontColor = new Color(color9);
            }
        }
    }
}