package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;

/* loaded from: classes.dex */
public class AlphaChannelBar extends ChannelBar {
    private GridSubImage gridImage;

    public AlphaChannelBar(PickerCommons commons, int mode, int maxValue, ChangeListener changeListener) {
        super(commons, mode, maxValue, changeListener);
        this.gridImage = new GridSubImage(commons.gridShader, commons.whiteTexture, commons.sizes.scaleFactor * 6.0f);
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ChannelBar, com.kotcrab.vis.ui.widget.color.internal.ShaderImage, com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        this.gridImage.draw(batch, this);
        super.draw(batch, parentAlpha);
    }
}