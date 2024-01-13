package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.scenes.scene2d.ui.Image;

/* loaded from: classes.dex */
public class GridSubImage {
    private ShaderProgram gridShader;
    private float gridSize;
    private Texture whiteTexture;

    public GridSubImage(ShaderProgram gridShader, Texture whiteTexture, float gridSize) {
        this.gridShader = gridShader;
        this.whiteTexture = whiteTexture;
        this.gridSize = gridSize;
    }

    public void draw(Batch batch, Image parent) {
        ShaderProgram originalShader = batch.getShader();
        batch.setShader(this.gridShader);
        this.gridShader.setUniformf("u_width", parent.getWidth());
        this.gridShader.setUniformf("u_height", parent.getHeight());
        this.gridShader.setUniformf("u_gridSize", this.gridSize);
        batch.draw(this.whiteTexture, parent.getX() + parent.getImageX(), parent.getY() + parent.getImageY(), parent.getImageWidth() * parent.getScaleX(), parent.getImageHeight() * parent.getScaleY());
        batch.setShader(originalShader);
    }
}