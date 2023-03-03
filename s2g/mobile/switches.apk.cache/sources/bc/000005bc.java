package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.NinePatch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.ui.Skin;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.VisUI;

/* loaded from: classes.dex */
public class VisImage extends Image {
    public VisImage() {
    }

    public VisImage(NinePatch patch) {
        super(patch);
    }

    public VisImage(TextureRegion region) {
        super(region);
    }

    public VisImage(Texture texture) {
        super(texture);
    }

    public VisImage(String drawableName) {
        super(VisUI.getSkin(), drawableName);
    }

    public VisImage(Skin skin, String drawableName) {
        super(skin, drawableName);
    }

    public VisImage(Drawable drawable) {
        super(drawable);
    }

    public VisImage(Drawable drawable, Scaling scaling) {
        super(drawable, scaling);
    }

    public VisImage(Drawable drawable, Scaling scaling, int align) {
        super(drawable, scaling, align);
    }

    public void setDrawable(Texture texture) {
        setDrawable(new TextureRegionDrawable(new TextureRegion(texture)));
    }
}