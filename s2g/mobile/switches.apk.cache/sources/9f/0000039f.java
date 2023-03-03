package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.NinePatch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.NinePatchDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable;
import com.badlogic.gdx.scenes.scene2d.utils.TransformDrawable;
import com.badlogic.gdx.utils.Scaling;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Image extends Widget {
    private int align;
    private Drawable drawable;
    private float imageHeight;
    private float imageWidth;
    private float imageX;
    private float imageY;
    private Scaling scaling;

    public Image() {
        this((Drawable) null);
    }

    public Image(NinePatch patch) {
        this(new NinePatchDrawable(patch), Scaling.stretch, 1);
    }

    public Image(TextureRegion region) {
        this(new TextureRegionDrawable(region), Scaling.stretch, 1);
    }

    public Image(Texture texture) {
        this(new TextureRegionDrawable(new TextureRegion(texture)));
    }

    public Image(Skin skin, String drawableName) {
        this(skin.getDrawable(drawableName), Scaling.stretch, 1);
    }

    public Image(Drawable drawable) {
        this(drawable, Scaling.stretch, 1);
    }

    public Image(Drawable drawable, Scaling scaling) {
        this(drawable, scaling, 1);
    }

    public Image(Drawable drawable, Scaling scaling, int align) {
        this.align = 1;
        setDrawable(drawable);
        this.scaling = scaling;
        this.align = align;
        setSize(getPrefWidth(), getPrefHeight());
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        Drawable drawable = this.drawable;
        if (drawable == null) {
            return;
        }
        float regionWidth = drawable.getMinWidth();
        float regionHeight = this.drawable.getMinHeight();
        float width = getWidth();
        float height = getHeight();
        Vector2 size = this.scaling.apply(regionWidth, regionHeight, width, height);
        this.imageWidth = size.x;
        this.imageHeight = size.y;
        int i = this.align;
        if ((i & 8) != 0) {
            this.imageX = 0.0f;
        } else if ((i & 16) != 0) {
            this.imageX = (int) (width - this.imageWidth);
        } else {
            this.imageX = (int) ((width / 2.0f) - (this.imageWidth / 2.0f));
        }
        int i2 = this.align;
        if ((i2 & 2) != 0) {
            this.imageY = (int) (height - this.imageHeight);
        } else if ((i2 & 4) != 0) {
            this.imageY = 0.0f;
        } else {
            this.imageY = (int) ((height / 2.0f) - (this.imageHeight / 2.0f));
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        validate();
        Color color = getColor();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        float x = getX();
        float y = getY();
        float scaleX = getScaleX();
        float scaleY = getScaleY();
        if (this.drawable instanceof TransformDrawable) {
            float rotation = getRotation();
            if (scaleX != 1.0f || scaleY != 1.0f || rotation != 0.0f) {
                ((TransformDrawable) this.drawable).draw(batch, x + this.imageX, y + this.imageY, getOriginX() - this.imageX, getOriginY() - this.imageY, this.imageWidth, this.imageHeight, scaleX, scaleY, rotation);
                return;
            }
        }
        Drawable drawable = this.drawable;
        if (drawable != null) {
            drawable.draw(batch, x + this.imageX, y + this.imageY, this.imageWidth * scaleX, this.imageHeight * scaleY);
        }
    }

    public void setDrawable(Skin skin, String drawableName) {
        setDrawable(skin.getDrawable(drawableName));
    }

    public void setDrawable(Drawable drawable) {
        if (this.drawable == drawable) {
            return;
        }
        if (drawable != null) {
            if (getPrefWidth() != drawable.getMinWidth() || getPrefHeight() != drawable.getMinHeight()) {
                invalidateHierarchy();
            }
        } else {
            invalidateHierarchy();
        }
        this.drawable = drawable;
    }

    public Drawable getDrawable() {
        return this.drawable;
    }

    public void setScaling(Scaling scaling) {
        if (scaling == null) {
            throw new IllegalArgumentException("scaling cannot be null.");
        }
        this.scaling = scaling;
        invalidate();
    }

    public void setAlign(int align) {
        this.align = align;
        invalidate();
    }

    public int getAlign() {
        return this.align;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinWidth() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getMinHeight() {
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        Drawable drawable = this.drawable;
        if (drawable != null) {
            return drawable.getMinWidth();
        }
        return 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        Drawable drawable = this.drawable;
        if (drawable != null) {
            return drawable.getMinHeight();
        }
        return 0.0f;
    }

    public float getImageX() {
        return this.imageX;
    }

    public float getImageY() {
        return this.imageY;
    }

    public float getImageWidth() {
        return this.imageWidth;
    }

    public float getImageHeight() {
        return this.imageHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
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
        sb.append(className.indexOf(36) != -1 ? "Image " : BuildConfig.FLAVOR);
        sb.append(className);
        sb.append(": ");
        sb.append(this.drawable);
        return sb.toString();
    }
}