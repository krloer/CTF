package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.ui.TextButton;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ImageTextButton extends Button {
    private final Image image;
    private Label label;
    private ImageTextButtonStyle style;

    public ImageTextButton(String text, Skin skin) {
        this(text, (ImageTextButtonStyle) skin.get(ImageTextButtonStyle.class));
        setSkin(skin);
    }

    public ImageTextButton(String text, Skin skin, String styleName) {
        this(text, (ImageTextButtonStyle) skin.get(styleName, ImageTextButtonStyle.class));
        setSkin(skin);
    }

    public ImageTextButton(String text, ImageTextButtonStyle style) {
        super(style);
        this.style = style;
        defaults().space(3.0f);
        this.image = new Image();
        this.image.setScaling(Scaling.fit);
        this.label = new Label(text, new Label.LabelStyle(style.font, style.fontColor));
        this.label.setAlignment(1);
        add((ImageTextButton) this.image);
        add((ImageTextButton) this.label);
        setStyle(style);
        setSize(getPrefWidth(), getPrefHeight());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof ImageTextButtonStyle)) {
            throw new IllegalArgumentException("style must be a ImageTextButtonStyle.");
        }
        this.style = (ImageTextButtonStyle) style;
        super.setStyle(style);
        if (this.image != null) {
            updateImage();
        }
        Label label = this.label;
        if (label != null) {
            ImageTextButtonStyle textButtonStyle = (ImageTextButtonStyle) style;
            Label.LabelStyle labelStyle = label.getStyle();
            labelStyle.font = textButtonStyle.font;
            labelStyle.fontColor = getFontColor();
            this.label.setStyle(labelStyle);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public ImageTextButtonStyle getStyle() {
        return this.style;
    }

    protected Drawable getImageDrawable() {
        if (!isDisabled() || this.style.imageDisabled == null) {
            if (isPressed()) {
                if (isChecked() && this.style.imageCheckedDown != null) {
                    return this.style.imageCheckedDown;
                }
                if (this.style.imageDown != null) {
                    return this.style.imageDown;
                }
            }
            if (isOver()) {
                if (isChecked()) {
                    if (this.style.imageCheckedOver != null) {
                        return this.style.imageCheckedOver;
                    }
                } else if (this.style.imageOver != null) {
                    return this.style.imageOver;
                }
            }
            if (isChecked()) {
                if (this.style.imageChecked != null) {
                    return this.style.imageChecked;
                }
                if (isOver() && this.style.imageOver != null) {
                    return this.style.imageOver;
                }
            }
            return this.style.imageUp;
        }
        return this.style.imageDisabled;
    }

    protected void updateImage() {
        this.image.setDrawable(getImageDrawable());
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
        updateImage();
        this.label.getStyle().fontColor = getFontColor();
        super.draw(batch, parentAlpha);
    }

    public Image getImage() {
        return this.image;
    }

    public Cell getImageCell() {
        return getCell(this.image);
    }

    public void setLabel(Label label) {
        getLabelCell().setActor(label);
        this.label = label;
    }

    public Label getLabel() {
        return this.label;
    }

    public Cell getLabelCell() {
        return getCell(this.label);
    }

    public void setText(CharSequence text) {
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
        sb.append(className.indexOf(36) != -1 ? "ImageTextButton " : BuildConfig.FLAVOR);
        sb.append(className);
        sb.append(": ");
        sb.append(this.image.getDrawable());
        sb.append(" ");
        sb.append((Object) this.label.getText());
        return sb.toString();
    }

    /* loaded from: classes.dex */
    public static class ImageTextButtonStyle extends TextButton.TextButtonStyle {
        public Drawable imageChecked;
        public Drawable imageCheckedDown;
        public Drawable imageCheckedOver;
        public Drawable imageDisabled;
        public Drawable imageDown;
        public Drawable imageOver;
        public Drawable imageUp;

        public ImageTextButtonStyle() {
        }

        public ImageTextButtonStyle(Drawable up, Drawable down, Drawable checked, BitmapFont font) {
            super(up, down, checked, font);
        }

        public ImageTextButtonStyle(ImageTextButtonStyle style) {
            super(style);
            this.imageUp = style.imageUp;
            this.imageDown = style.imageDown;
            this.imageOver = style.imageOver;
            this.imageDisabled = style.imageDisabled;
            this.imageChecked = style.imageChecked;
            this.imageCheckedDown = style.imageCheckedDown;
            this.imageCheckedOver = style.imageCheckedOver;
        }

        public ImageTextButtonStyle(TextButton.TextButtonStyle style) {
            super(style);
        }
    }
}