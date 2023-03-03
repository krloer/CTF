package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.kotcrab.vis.ui.widget.VisImage;

/* loaded from: classes.dex */
public class AlphaImage extends VisImage {
    private GridSubImage gridImage;

    public AlphaImage(PickerCommons commons, float gridSize) {
        super(commons.whiteTexture);
        this.gridImage = new GridSubImage(commons.gridShader, commons.whiteTexture, gridSize);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        if (getColor().a != 1.0f) {
            this.gridImage.draw(batch, this);
        }
        super.draw(batch, parentAlpha);
    }
}