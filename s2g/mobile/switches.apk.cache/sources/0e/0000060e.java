package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Pools;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.widget.color.ColorPickerWidgetStyle;

/* loaded from: classes.dex */
public class Palette extends ShaderImage {
    private int maxValue;
    private float pickerHue;
    private float selectorX;
    private float selectorY;
    private Sizes sizes;
    private ColorPickerWidgetStyle style;
    private int xV;
    private int yS;

    public Palette(PickerCommons commons, int maxValue, ChangeListener listener) {
        super(commons.paletteShader, commons.whiteTexture);
        this.style = commons.style;
        this.sizes = commons.sizes;
        this.maxValue = maxValue;
        setValue(0, 0);
        addListener(listener);
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.Palette.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Palette.this.updateValueFromTouch(x, y);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                Palette.this.updateValueFromTouch(x, y);
            }
        });
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ShaderImage, com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        this.style.verticalSelector.draw(batch, getX(), ((getY() + this.selectorY) - (this.style.verticalSelector.getMinHeight() / 2.0f)) + 0.1f, getImageWidth(), this.style.verticalSelector.getMinHeight());
        this.style.horizontalSelector.draw(batch, ((getX() + this.selectorX) - (this.style.horizontalSelector.getMinWidth() / 2.0f)) + 0.1f, getY(), this.style.horizontalSelector.getMinWidth(), getImageHeight());
        this.style.cross.draw(batch, ((getX() + this.selectorX) - (this.style.cross.getMinWidth() / 2.0f)) + 0.1f, ((getY() + this.selectorY) - (this.style.cross.getMinHeight() / 2.0f)) + 0.1f, this.style.cross.getMinWidth(), this.style.cross.getMinHeight());
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ShaderImage
    protected void setShaderUniforms(ShaderProgram shader) {
        shader.setUniformf("u_h", this.pickerHue);
    }

    public void setPickerHue(int pickerHue) {
        this.pickerHue = pickerHue / 360.0f;
    }

    public void setValue(int s, int v) {
        this.xV = v;
        this.yS = s;
        if (this.xV < 0) {
            this.xV = 0;
        }
        int i = this.xV;
        int i2 = this.maxValue;
        if (i > i2) {
            this.xV = i2;
        }
        if (this.yS < 0) {
            this.yS = 0;
        }
        int i3 = this.yS;
        int i4 = this.maxValue;
        if (i3 > i4) {
            this.yS = i4;
        }
        this.selectorX = (this.xV / this.maxValue) * 160.0f * this.sizes.scaleFactor;
        this.selectorY = (this.yS / this.maxValue) * 160.0f * this.sizes.scaleFactor;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateValueFromTouch(float touchX, float touchY) {
        int newV = (int) (((touchX / 160.0f) * this.maxValue) / this.sizes.scaleFactor);
        int newS = (int) (((touchY / 160.0f) * this.maxValue) / this.sizes.scaleFactor);
        setValue(newS, newV);
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        fire(changeEvent);
        Pools.free(changeEvent);
    }

    public int getV() {
        return this.xV;
    }

    public int getS() {
        return this.yS;
    }
}