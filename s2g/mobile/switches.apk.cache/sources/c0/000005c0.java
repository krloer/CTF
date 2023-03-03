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
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.BorderOwner;
import com.kotcrab.vis.ui.widget.VisTextButton;

/* loaded from: classes.dex */
public class VisImageTextButton extends Button implements Focusable, BorderOwner {
    private boolean drawBorder;
    private boolean focusBorderEnabled;
    private Image image;
    private Label label;
    private VisImageTextButtonStyle style;

    public VisImageTextButton(String text, Drawable imageUp) {
        this(text, "default", imageUp, null);
    }

    public VisImageTextButton(String text, String styleName, Drawable imageUp) {
        this(text, styleName, imageUp, null);
    }

    public VisImageTextButton(String text, String styleName, Drawable imageUp, Drawable imageDown) {
        super(new VisImageTextButtonStyle((VisImageTextButtonStyle) VisUI.getSkin().get(styleName, VisImageTextButtonStyle.class)));
        this.focusBorderEnabled = true;
        VisImageTextButtonStyle visImageTextButtonStyle = this.style;
        visImageTextButtonStyle.imageUp = imageUp;
        visImageTextButtonStyle.imageDown = imageDown;
        init(text);
    }

    public VisImageTextButton(String text, String styleName) {
        super(new VisImageTextButtonStyle((VisImageTextButtonStyle) VisUI.getSkin().get(styleName, VisImageTextButtonStyle.class)));
        this.focusBorderEnabled = true;
        init(text);
    }

    public VisImageTextButton(String text, VisImageTextButtonStyle style) {
        super(style);
        this.focusBorderEnabled = true;
        init(text);
    }

    private void init(String text) {
        defaults().space(3.0f);
        this.image = new Image();
        this.image.setScaling(Scaling.fit);
        add((VisImageTextButton) this.image);
        this.label = new Label(text, new Label.LabelStyle(this.style.font, this.style.fontColor));
        this.label.setAlignment(1);
        add((VisImageTextButton) this.label);
        setStyle(this.style);
        setSize(getPrefWidth(), getPrefHeight());
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisImageTextButton.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (!VisImageTextButton.this.isDisabled()) {
                    FocusManager.switchFocus(VisImageTextButton.this.getStage(), VisImageTextButton.this);
                    return false;
                }
                return false;
            }
        });
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof VisImageTextButtonStyle)) {
            throw new IllegalArgumentException("style must be a VisImageTextButtonStyle.");
        }
        super.setStyle(style);
        this.style = (VisImageTextButtonStyle) style;
        if (this.image != null) {
            updateImage();
        }
        Label label = this.label;
        if (label != null) {
            VisImageTextButtonStyle textButtonStyle = (VisImageTextButtonStyle) style;
            Label.LabelStyle labelStyle = label.getStyle();
            labelStyle.font = textButtonStyle.font;
            labelStyle.fontColor = textButtonStyle.fontColor;
            this.label.setStyle(labelStyle);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public VisImageTextButtonStyle getStyle() {
        return this.style;
    }

    private void updateImage() {
        Drawable drawable = null;
        if (isDisabled() && this.style.imageDisabled != null) {
            drawable = this.style.imageDisabled;
        } else if (isPressed() && this.style.imageDown != null) {
            drawable = this.style.imageDown;
        } else if (isChecked() && this.style.imageChecked != null) {
            drawable = (this.style.imageCheckedOver == null || !isOver()) ? this.style.imageChecked : this.style.imageCheckedOver;
        } else if (isOver() && this.style.imageOver != null) {
            drawable = this.style.imageOver;
        } else if (this.style.imageUp != null) {
            drawable = this.style.imageUp;
        }
        this.image.setDrawable(drawable);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Color fontColor;
        updateImage();
        if (isDisabled() && this.style.disabledFontColor != null) {
            fontColor = this.style.disabledFontColor;
        } else if (isPressed() && this.style.downFontColor != null) {
            fontColor = this.style.downFontColor;
        } else if (isChecked() && this.style.checkedFontColor != null) {
            fontColor = (!isOver() || this.style.checkedOverFontColor == null) ? this.style.checkedFontColor : this.style.checkedOverFontColor;
        } else if (isOver() && this.style.overFontColor != null) {
            fontColor = this.style.overFontColor;
        } else {
            fontColor = this.style.fontColor;
        }
        if (fontColor != null) {
            this.label.getStyle().fontColor = fontColor;
        }
        super.draw(batch, parentAlpha);
        if (this.focusBorderEnabled && this.drawBorder && this.style.focusBorder != null) {
            this.style.focusBorder.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
    }

    public Image getImage() {
        return this.image;
    }

    public Cell getImageCell() {
        return getCell(this.image);
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
        return super.toString() + ": " + ((Object) this.label.getText());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean disabled) {
        super.setDisabled(disabled);
        if (disabled) {
            FocusManager.resetFocus(getStage(), this);
        }
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
    public static class VisImageTextButtonStyle extends VisTextButton.VisTextButtonStyle {
        public Drawable imageChecked;
        public Drawable imageCheckedOver;
        public Drawable imageDisabled;
        public Drawable imageDown;
        public Drawable imageOver;
        public Drawable imageUp;

        public VisImageTextButtonStyle() {
        }

        public VisImageTextButtonStyle(Drawable up, Drawable down, Drawable checked, BitmapFont font) {
            super(up, down, checked, font);
        }

        public VisImageTextButtonStyle(VisImageTextButtonStyle style) {
            super(style);
            Drawable drawable = style.imageUp;
            if (drawable != null) {
                this.imageUp = drawable;
            }
            Drawable drawable2 = style.imageDown;
            if (drawable2 != null) {
                this.imageDown = drawable2;
            }
            Drawable drawable3 = style.imageOver;
            if (drawable3 != null) {
                this.imageOver = drawable3;
            }
            Drawable drawable4 = style.imageChecked;
            if (drawable4 != null) {
                this.imageChecked = drawable4;
            }
            Drawable drawable5 = style.imageCheckedOver;
            if (drawable5 != null) {
                this.imageCheckedOver = drawable5;
            }
            Drawable drawable6 = style.imageDisabled;
            if (drawable6 != null) {
                this.imageDisabled = drawable6;
            }
        }

        public VisImageTextButtonStyle(VisTextButton.VisTextButtonStyle style) {
            super(style);
        }
    }
}