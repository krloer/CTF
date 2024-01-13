package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.BorderOwner;
import com.kotcrab.vis.ui.widget.Tooltip;

/* loaded from: classes.dex */
public class VisImageButton extends Button implements Focusable, BorderOwner {
    private boolean drawBorder;
    private boolean focusBorderEnabled;
    private boolean generateDisabledImage;
    private Image image;
    private VisImageButtonStyle style;

    public VisImageButton(Drawable imageUp) {
        this(imageUp, null, null);
    }

    public VisImageButton(Drawable imageUp, String tooltipText) {
        this(imageUp, null, null);
        if (tooltipText != null) {
            new Tooltip.Builder(tooltipText).target(this).build();
        }
    }

    public VisImageButton(Drawable imageUp, Drawable imageDown) {
        this(imageUp, imageDown, null);
    }

    public VisImageButton(Drawable imageUp, Drawable imageDown, Drawable imageChecked) {
        super(new VisImageButtonStyle((VisImageButtonStyle) VisUI.getSkin().get(VisImageButtonStyle.class)));
        this.focusBorderEnabled = true;
        this.generateDisabledImage = false;
        VisImageButtonStyle visImageButtonStyle = this.style;
        visImageButtonStyle.imageUp = imageUp;
        visImageButtonStyle.imageDown = imageDown;
        visImageButtonStyle.imageChecked = imageChecked;
        init();
    }

    public VisImageButton(String styleName) {
        super(new VisImageButtonStyle((VisImageButtonStyle) VisUI.getSkin().get(styleName, VisImageButtonStyle.class)));
        this.focusBorderEnabled = true;
        this.generateDisabledImage = false;
        init();
    }

    public VisImageButton(VisImageButtonStyle style) {
        super(style);
        this.focusBorderEnabled = true;
        this.generateDisabledImage = false;
        init();
    }

    private void init() {
        this.image = new Image();
        this.image.setScaling(Scaling.fit);
        add((VisImageButton) this.image);
        setSize(getPrefWidth(), getPrefHeight());
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.VisImageButton.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (!VisImageButton.this.isDisabled()) {
                    FocusManager.switchFocus(VisImageButton.this.getStage(), VisImageButton.this);
                    return false;
                }
                return false;
            }
        });
        updateImage();
    }

    public void setGenerateDisabledImage(boolean generate) {
        this.generateDisabledImage = generate;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public VisImageButtonStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof VisImageButtonStyle)) {
            throw new IllegalArgumentException("style must be an ImageButtonStyle.");
        }
        super.setStyle(style);
        this.style = (VisImageButtonStyle) style;
        if (this.image != null) {
            updateImage();
        }
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
        if (this.generateDisabledImage && this.style.imageDisabled == null && isDisabled()) {
            this.image.setColor(Color.GRAY);
        } else {
            this.image.setColor(Color.WHITE);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        updateImage();
        super.draw(batch, parentAlpha);
        if (this.focusBorderEnabled && this.drawBorder && this.style.focusBorder != null) {
            this.style.focusBorder.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
    }

    public Image getImage() {
        return this.image;
    }

    public Cell<?> getImageCell() {
        return getCell(this.image);
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
    public static class VisImageButtonStyle extends Button.ButtonStyle {
        public Drawable focusBorder;
        public Drawable imageChecked;
        public Drawable imageCheckedOver;
        public Drawable imageDisabled;
        public Drawable imageDown;
        public Drawable imageOver;
        public Drawable imageUp;

        public VisImageButtonStyle() {
        }

        public VisImageButtonStyle(Drawable up, Drawable down, Drawable checked, Drawable imageUp, Drawable imageDown, Drawable imageChecked) {
            super(up, down, checked);
            this.imageUp = imageUp;
            this.imageDown = imageDown;
            this.imageChecked = imageChecked;
        }

        public VisImageButtonStyle(VisImageButtonStyle style) {
            super(style);
            this.imageUp = style.imageUp;
            this.imageDown = style.imageDown;
            this.imageOver = style.imageOver;
            this.imageChecked = style.imageChecked;
            this.imageCheckedOver = style.imageCheckedOver;
            this.imageDisabled = style.imageDisabled;
            this.focusBorder = style.focusBorder;
        }
    }
}