package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Pools;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.widget.color.ColorPickerWidgetStyle;

/* loaded from: classes.dex */
public class VerticalChannelBar extends ShaderImage {
    private int maxValue;
    private float selectorY;
    private Sizes sizes;
    private ColorPickerWidgetStyle style;
    private int value;

    public VerticalChannelBar(PickerCommons commons, int maxValue, ChangeListener listener) {
        super(commons.verticalChannelShader, commons.whiteTexture);
        this.style = commons.style;
        this.sizes = commons.sizes;
        this.maxValue = maxValue;
        setValue(0);
        addListener(listener);
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.VerticalChannelBar.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                VerticalChannelBar.this.updateValueFromTouch(y);
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                VerticalChannelBar.this.updateValueFromTouch(y);
            }
        });
    }

    @Override // com.kotcrab.vis.ui.widget.color.internal.ShaderImage, com.badlogic.gdx.scenes.scene2d.ui.Image, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        super.draw(batch, parentAlpha);
        this.style.verticalSelector.draw(batch, getX(), ((getY() + getImageY()) + this.selectorY) - 2.5f, getImageWidth(), this.style.verticalSelector.getMinHeight());
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
        this.selectorY = (this.value / this.maxValue) * 160.0f * this.sizes.scaleFactor;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateValueFromTouch(float y) {
        int newValue = (int) (((y / 160.0f) * this.maxValue) / this.sizes.scaleFactor);
        setValue(newValue);
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        fire(changeEvent);
        Pools.free(changeEvent);
    }

    public int getValue() {
        return this.value;
    }
}