package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

/* loaded from: classes.dex */
public class TiledDrawable extends TextureRegionDrawable {
    private final Color color;
    private float scale;

    public TiledDrawable() {
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scale = 1.0f;
    }

    public TiledDrawable(TextureRegion region) {
        super(region);
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scale = 1.0f;
    }

    public TiledDrawable(TextureRegionDrawable drawable) {
        super(drawable);
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.scale = 1.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable, com.badlogic.gdx.scenes.scene2d.utils.BaseDrawable, com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void draw(Batch batch, float x, float y, float width, float height) {
        int fullX;
        float y2;
        float oldColor = batch.getPackedColor();
        batch.setColor(batch.getColor().mul(this.color));
        TextureRegion region = getRegion();
        float regionWidth = region.getRegionWidth() * this.scale;
        float regionHeight = region.getRegionHeight() * this.scale;
        int fullX2 = (int) (width / regionWidth);
        int fullY = (int) (height / regionHeight);
        float remainingX = width - (fullX2 * regionWidth);
        float remainingY = height - (fullY * regionHeight);
        float f = (x + width) - remainingX;
        float f2 = (y + height) - remainingY;
        float x2 = x;
        int i = 0;
        float y3 = y;
        while (i < fullX2) {
            float y4 = y;
            for (int ii = 0; ii < fullY; ii++) {
                batch.draw(region, x2, y4, regionWidth, regionHeight);
                y4 += regionHeight;
            }
            x2 += regionWidth;
            i++;
            y3 = y4;
        }
        Texture texture = region.getTexture();
        float u = region.getU();
        float v2 = region.getV2();
        if (remainingX > 0.0f) {
            float u2 = u + (remainingX / (texture.getWidth() * this.scale));
            float v = region.getV();
            y2 = y;
            int ii2 = 0;
            while (ii2 < fullY) {
                batch.draw(texture, x2, y2, remainingX, regionHeight, u, v2, u2, v);
                y2 += regionHeight;
                ii2++;
                fullX2 = fullX2;
                fullY = fullY;
            }
            fullX = fullX2;
            if (remainingY > 0.0f) {
                float v3 = v2 - (remainingY / (texture.getHeight() * this.scale));
                batch.draw(texture, x2, y2, remainingX, remainingY, u, v2, u2, v3);
            }
        } else {
            fullX = fullX2;
            y2 = y3;
        }
        if (remainingY > 0.0f) {
            float u22 = region.getU2();
            float v4 = v2 - (remainingY / (texture.getHeight() * this.scale));
            float x3 = x;
            for (int i2 = 0; i2 < fullX; i2++) {
                batch.draw(texture, x3, y2, regionWidth, remainingY, u, v2, u22, v4);
                x3 += regionWidth;
            }
        }
        batch.setPackedColor(oldColor);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable, com.badlogic.gdx.scenes.scene2d.utils.TransformDrawable
    public void draw(Batch batch, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        throw new UnsupportedOperationException();
    }

    public Color getColor() {
        return this.color;
    }

    public void setScale(float scale) {
        this.scale = scale;
    }

    public float getScale() {
        return this.scale;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable
    public TiledDrawable tint(Color tint) {
        TiledDrawable drawable = new TiledDrawable(this);
        drawable.color.set(tint);
        drawable.setLeftWidth(getLeftWidth());
        drawable.setRightWidth(getRightWidth());
        drawable.setTopHeight(getTopHeight());
        drawable.setBottomHeight(getBottomHeight());
        return drawable;
    }
}