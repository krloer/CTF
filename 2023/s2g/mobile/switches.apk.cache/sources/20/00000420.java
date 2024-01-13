package com.badlogic.gdx.scenes.scene2d.utils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.Sprite;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

/* loaded from: classes.dex */
public class TextureRegionDrawable extends BaseDrawable implements TransformDrawable {
    private TextureRegion region;

    public TextureRegionDrawable() {
    }

    public TextureRegionDrawable(Texture texture) {
        setRegion(new TextureRegion(texture));
    }

    public TextureRegionDrawable(TextureRegion region) {
        setRegion(region);
    }

    public TextureRegionDrawable(TextureRegionDrawable drawable) {
        super(drawable);
        setRegion(drawable.region);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.BaseDrawable, com.badlogic.gdx.scenes.scene2d.utils.Drawable
    public void draw(Batch batch, float x, float y, float width, float height) {
        batch.draw(this.region, x, y, width, height);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.TransformDrawable
    public void draw(Batch batch, float x, float y, float originX, float originY, float width, float height, float scaleX, float scaleY, float rotation) {
        batch.draw(this.region, x, y, originX, originY, width, height, scaleX, scaleY, rotation);
    }

    public void setRegion(TextureRegion region) {
        this.region = region;
        if (region != null) {
            setMinWidth(region.getRegionWidth());
            setMinHeight(region.getRegionHeight());
        }
    }

    public TextureRegion getRegion() {
        return this.region;
    }

    public Drawable tint(Color tint) {
        Sprite sprite;
        TextureRegion textureRegion = this.region;
        if (textureRegion instanceof TextureAtlas.AtlasRegion) {
            sprite = new TextureAtlas.AtlasSprite((TextureAtlas.AtlasRegion) textureRegion);
        } else {
            sprite = new Sprite(textureRegion);
        }
        sprite.setColor(tint);
        sprite.setSize(getMinWidth(), getMinHeight());
        SpriteDrawable drawable = new SpriteDrawable(sprite);
        drawable.setLeftWidth(getLeftWidth());
        drawable.setRightWidth(getRightWidth());
        drawable.setTopHeight(getTopHeight());
        drawable.setBottomHeight(getBottomHeight());
        return drawable;
    }
}