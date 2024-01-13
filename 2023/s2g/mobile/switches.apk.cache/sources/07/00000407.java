package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.utils.reflect.ClassReflection;

/* loaded from: classes.dex */
public class BaseDrawable implements Drawable {
    private float bottomHeight;
    private float leftWidth;
    private float minHeight;
    private float minWidth;
    private String name;
    private float rightWidth;
    private float topHeight;

    public BaseDrawable() {
    }

    public BaseDrawable(Drawable drawable) {
        if (drawable instanceof BaseDrawable) {
            this.name = ((BaseDrawable) drawable).getName();
        }
        this.leftWidth = drawable.getLeftWidth();
        this.rightWidth = drawable.getRightWidth();
        this.topHeight = drawable.getTopHeight();
        this.bottomHeight = drawable.getBottomHeight();
        this.minWidth = drawable.getMinWidth();
        this.minHeight = drawable.getMinHeight();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void draw(Batch batch, float x, float y, float width, float height) {
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getLeftWidth() {
        return this.leftWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setLeftWidth(float leftWidth) {
        this.leftWidth = leftWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getRightWidth() {
        return this.rightWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setRightWidth(float rightWidth) {
        this.rightWidth = rightWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getTopHeight() {
        return this.topHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setTopHeight(float topHeight) {
        this.topHeight = topHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getBottomHeight() {
        return this.bottomHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setBottomHeight(float bottomHeight) {
        this.bottomHeight = bottomHeight;
    }

    public void setPadding(float topHeight, float leftWidth, float bottomHeight, float rightWidth) {
        setTopHeight(topHeight);
        setLeftWidth(leftWidth);
        setBottomHeight(bottomHeight);
        setRightWidth(rightWidth);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getMinWidth() {
        return this.minWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setMinWidth(float minWidth) {
        this.minWidth = minWidth;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public float getMinHeight() {
        return this.minHeight;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void setMinHeight(float minHeight) {
        this.minHeight = minHeight;
    }

    public void setMinSize(float minWidth, float minHeight) {
        setMinWidth(minWidth);
        setMinHeight(minHeight);
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String toString() {
        String str = this.name;
        return str == null ? ClassReflection.getSimpleName(getClass()) : str;
    }
}