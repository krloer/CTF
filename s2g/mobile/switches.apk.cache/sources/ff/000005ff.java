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
public class ChannelBar extends ShaderImage {
    public static final int MODE_ALPHA = 0;
    public static final int MODE_B = 3;
    public static final int MODE_G = 2;
    public static final int MODE_H = 4;
    public static final int MODE_R = 1;
    public static final int MODE_S = 5;
    public static final int MODE_V = 6;
    private ChannelBarListener channelBarListener;
    private int maxValue;
    private int mode;
    private float selectorX;
    private Sizes sizes;
    protected ColorPickerWidgetStyle style;
    private int value;

    /* loaded from: classes.dex */
    public interface ChannelBarListener {
        void setShaderUniforms(ShaderProgram shaderProgram);

        void updateFields();
    }

    public ChannelBar(PickerCommons commons, int mode, int maxValue, ChangeListener changeListener) {
        super(commons.getBarShader(mode), commons.whiteTexture);
        this.style = commons.style;
        this.sizes = commons.sizes;
        this.mode = mode;
        this.maxValue = maxValue;
        setValue(this.value);
        addListener(changeListener);
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ChannelBar.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                ChannelBar.this.updateValueFromTouch(x);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                ChannelBar.this.updateValueFromTouch(x);
            }
        });
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ShaderImage, com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        this.style.barSelector.draw(batch, (getX() + this.selectorX) - (this.style.barSelector.getMinWidth() / 2.0f), getY() - 1.0f, this.style.barSelector.getMinWidth(), this.style.barSelector.getMinHeight());
    }

    public void setValue(int newValue) {
        this.value = newValue;
        if (this.value < 0) {
            this.value = 0;
        }
        int i = this.value;
        int i2 = this.maxValue;
        if (i > i2) {
            this.value = i2;
        }
        this.selectorX = (this.value / this.maxValue) * 130.0f * this.sizes.scaleFactor;
    }

    public int getValue() {
        return this.value;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateValueFromTouch(float x) {
        int newValue = (int) (((x / 130.0f) * this.maxValue) / this.sizes.scaleFactor);
        setValue(newValue);
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        fire(changeEvent);
        Pools.free(changeEvent);
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ShaderImage
    protected void setShaderUniforms(ShaderProgram shader) {
        shader.setUniformi("u_mode", this.mode);
        this.channelBarListener.setShaderUniforms(shader);
    }

    public void setChannelBarListener(ChannelBarListener channelBarListener) {
        this.channelBarListener = channelBarListener;
    }
}