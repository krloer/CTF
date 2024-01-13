package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ImageButton extends Button {
    private final Image image;
    private ImageButtonStyle style;

    public ImageButton(Skin skin) {
        this((ImageButtonStyle) skin.get(ImageButtonStyle.class));
        setSkin(skin);
    }

    public ImageButton(Skin skin, String styleName) {
        this((ImageButtonStyle) skin.get(styleName, ImageButtonStyle.class));
        setSkin(skin);
    }

    public ImageButton(ImageButtonStyle style) {
        super(style);
        this.image = new Image();
        this.image.setScaling(Scaling.fit);
        add((ImageButton) this.image);
        setStyle(style);
        setSize(getPrefWidth(), getPrefHeight());
    }

    public ImageButton(Drawable imageUp) {
        this(new ImageButtonStyle(null, null, null, imageUp, null, null));
    }

    public ImageButton(Drawable imageUp, Drawable imageDown) {
        this(new ImageButtonStyle(null, null, null, imageUp, imageDown, null));
    }

    public ImageButton(Drawable imageUp, Drawable imageDown, Drawable imageChecked) {
        this(new ImageButtonStyle(null, null, null, imageUp, imageDown, imageChecked));
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public void setStyle(Button.ButtonStyle style) {
        if (!(style instanceof ImageButtonStyle)) {
            throw new IllegalArgumentException("style must be an ImageButtonStyle.");
        }
        this.style = (ImageButtonStyle) style;
        super.setStyle(style);
        if (this.image != null) {
            updateImage();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button
    public ImageButtonStyle getStyle() {
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

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Button, com.badlogic.gdx.scenes.scene2d.ui.Table, com.badlogic.gdx.scenes.scene2d.ui.WidgetGroup, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        updateImage();
        super.draw(batch, parentAlpha);
    }

    public Image getImage() {
        return this.image;
    }

    public Cell getImageCell() {
        return getCell(this.image);
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
        sb.append(className.indexOf(36) != -1 ? "ImageButton " : BuildConfig.FLAVOR);
        sb.append(className);
        sb.append(": ");
        sb.append(this.image.getDrawable());
        return sb.toString();
    }

    /* loaded from: classes.dex */
    public static class ImageButtonStyle extends Button.ButtonStyle {
        public Drawable imageChecked;
        public Drawable imageCheckedDown;
        public Drawable imageCheckedOver;
        public Drawable imageDisabled;
        public Drawable imageDown;
        public Drawable imageOver;
        public Drawable imageUp;

        public ImageButtonStyle() {
        }

        public ImageButtonStyle(Drawable up, Drawable down, Drawable checked, Drawable imageUp, Drawable imageDown, Drawable imageChecked) {
            super(up, down, checked);
            this.imageUp = imageUp;
            this.imageDown = imageDown;
            this.imageChecked = imageChecked;
        }

        public ImageButtonStyle(ImageButtonStyle style) {
            super(style);
            this.imageUp = style.imageUp;
            this.imageDown = style.imageDown;
            this.imageOver = style.imageOver;
            this.imageDisabled = style.imageDisabled;
            this.imageChecked = style.imageChecked;
            this.imageCheckedDown = style.imageCheckedDown;
            this.imageCheckedOver = style.imageCheckedOver;
        }

        public ImageButtonStyle(Button.ButtonStyle style) {
            super(style);
        }
    }
}