package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.kotcrab.vis.ui.widget.VisImage;

/* loaded from: classes.dex */
public class ShaderImage extends VisImage {
    private ShaderProgram shader;

    public ShaderImage(ShaderProgram shader, Texture texture) {
        super(texture);
        this.shader = shader;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        ShaderProgram originalShader = batch.getShader();
        batch.setShader(this.shader);
        setShaderUniforms(this.shader);
        super.draw(batch, parentAlpha);
        batch.setShader(originalShader);
    }

    protected void setShaderUniforms(ShaderProgram shader) {
    }
}