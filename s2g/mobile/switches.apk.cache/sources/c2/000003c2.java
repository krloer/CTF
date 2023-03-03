package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.ProgressBar;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Pools;

/* loaded from: classes.dex */
public class Slider extends ProgressBar {
    int button;
    int draggingPointer;
    boolean mouseOver;
    private float[] snapValues;
    private float threshold;
    private Interpolation visualInterpolationInverse;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public Slider(float r8, float r9, float r10, boolean r11, com.badlogic.gdx.scenes.scene2d.ui.Skin r12) {
        /*
            r7 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "default-"
            r0.append(r1)
            if (r11 == 0) goto Lf
            java.lang.String r1 = "vertical"
            goto L11
        Lf:
            java.lang.String r1 = "horizontal"
        L11:
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            java.lang.Class<com.badlogic.gdx.scenes.scene2d.ui.Slider$SliderStyle> r1 = com.badlogic.gdx.scenes.scene2d.ui.Slider.SliderStyle.class
            java.lang.Object r0 = r12.get(r0, r1)
            r6 = r0
            com.badlogic.gdx.scenes.scene2d.ui.Slider$SliderStyle r6 = (com.badlogic.gdx.scenes.scene2d.ui.Slider.SliderStyle) r6
            r1 = r7
            r2 = r8
            r3 = r9
            r4 = r10
            r5 = r11
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.scenes.scene2d.ui.Slider.<init>(float, float, float, boolean, com.badlogic.gdx.scenes.scene2d.ui.Skin):void");
    }

    public Slider(float min, float max, float stepSize, boolean vertical, Skin skin, String styleName) {
        this(min, max, stepSize, vertical, (SliderStyle) skin.get(styleName, SliderStyle.class));
    }

    public Slider(float min, float max, float stepSize, boolean vertical, SliderStyle style) {
        super(min, max, stepSize, vertical, style);
        this.button = -1;
        this.draggingPointer = -1;
        this.visualInterpolationInverse = Interpolation.linear;
        addListener(new InputListener() { // from class: com.badlogic.gdx.scenes.scene2d.ui.Slider.1
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (Slider.this.disabled) {
                    return false;
                }
                if ((Slider.this.button == -1 || Slider.this.button == button) && Slider.this.draggingPointer == -1) {
                    Slider slider = Slider.this;
                    slider.draggingPointer = pointer;
                    slider.calculatePositionAndValue(x, y);
                    return true;
                }
                return false;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (pointer != Slider.this.draggingPointer) {
                    return;
                }
                Slider.this.draggingPointer = -1;
                if (event.isTouchFocusCancel() || !Slider.this.calculatePositionAndValue(x, y)) {
                    ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
                    Slider.this.fire(changeEvent);
                    Pools.free(changeEvent);
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchDragged(InputEvent event, float x, float y, int pointer) {
                Slider.this.calculatePositionAndValue(x, y);
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                if (pointer == -1) {
                    Slider.this.mouseOver = true;
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                if (pointer == -1) {
                    Slider.this.mouseOver = false;
                }
            }
        });
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.ProgressBar
    public SliderStyle getStyle() {
        return (SliderStyle) super.getStyle();
    }

    public boolean isOver() {
        return this.mouseOver;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.ProgressBar
    protected Drawable getBackgroundDrawable() {
        SliderStyle style = (SliderStyle) super.getStyle();
        return (!this.disabled || style.disabledBackground == null) ? (!isDragging() || style.backgroundDown == null) ? (!this.mouseOver || style.backgroundOver == null) ? style.background : style.backgroundOver : style.backgroundDown : style.disabledBackground;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.ProgressBar
    protected Drawable getKnobDrawable() {
        SliderStyle style = (SliderStyle) super.getStyle();
        return (!this.disabled || style.disabledKnob == null) ? (!isDragging() || style.knobDown == null) ? (!this.mouseOver || style.knobOver == null) ? style.knob : style.knobOver : style.knobDown : style.disabledKnob;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.ProgressBar
    protected Drawable getKnobBeforeDrawable() {
        SliderStyle style = (SliderStyle) super.getStyle();
        return (!this.disabled || style.disabledKnobBefore == null) ? (!isDragging() || style.knobBeforeDown == null) ? (!this.mouseOver || style.knobBeforeOver == null) ? style.knobBefore : style.knobBeforeOver : style.knobBeforeDown : style.disabledKnobBefore;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.ProgressBar
    protected Drawable getKnobAfterDrawable() {
        SliderStyle style = (SliderStyle) super.getStyle();
        return (!this.disabled || style.disabledKnobAfter == null) ? (!isDragging() || style.knobAfterDown == null) ? (!this.mouseOver || style.knobAfterOver == null) ? style.knobAfter : style.knobAfterOver : style.knobAfterDown : style.disabledKnobAfter;
    }

    boolean calculatePositionAndValue(float x, float y) {
        float value;
        SliderStyle style = getStyle();
        Drawable knob = style.knob;
        Drawable bg = getBackgroundDrawable();
        float oldPosition = this.position;
        float min = getMinValue();
        float max = getMaxValue();
        if (this.vertical) {
            float height = (getHeight() - bg.getTopHeight()) - bg.getBottomHeight();
            float knobHeight = knob == null ? 0.0f : knob.getMinHeight();
            this.position = (y - bg.getBottomHeight()) - (0.5f * knobHeight);
            value = ((max - min) * this.visualInterpolationInverse.apply(this.position / (height - knobHeight))) + min;
            this.position = Math.max(Math.min(0.0f, bg.getBottomHeight()), this.position);
            this.position = Math.min(height - knobHeight, this.position);
        } else {
            float width = (getWidth() - bg.getLeftWidth()) - bg.getRightWidth();
            float knobWidth = knob == null ? 0.0f : knob.getMinWidth();
            this.position = (x - bg.getLeftWidth()) - (0.5f * knobWidth);
            value = ((max - min) * this.visualInterpolationInverse.apply(this.position / (width - knobWidth))) + min;
            this.position = Math.max(Math.min(0.0f, bg.getLeftWidth()), this.position);
            this.position = Math.min(width - knobWidth, this.position);
        }
        float width2 = value;
        if (!Gdx.input.isKeyPressed(59) && !Gdx.input.isKeyPressed(60)) {
            value = snap(value);
        }
        boolean valueSet = setValue(value);
        if (value == width2) {
            this.position = oldPosition;
        }
        return valueSet;
    }

    protected float snap(float value) {
        float[] fArr = this.snapValues;
        if (fArr == null || fArr.length == 0) {
            return value;
        }
        float bestDiff = -1.0f;
        float bestValue = 0.0f;
        int i = 0;
        while (true) {
            float[] fArr2 = this.snapValues;
            if (i >= fArr2.length) {
                break;
            }
            float snapValue = fArr2[i];
            float diff = Math.abs(value - snapValue);
            if (diff <= this.threshold && (bestDiff == -1.0f || diff < bestDiff)) {
                bestDiff = diff;
                bestValue = snapValue;
            }
            i++;
        }
        int i2 = (bestDiff > (-1.0f) ? 1 : (bestDiff == (-1.0f) ? 0 : -1));
        return i2 == 0 ? value : bestValue;
    }

    public void setSnapToValues(float[] values, float threshold) {
        this.snapValues = values;
        this.threshold = threshold;
    }

    public boolean isDragging() {
        return this.draggingPointer != -1;
    }

    public void setButton(int button) {
        this.button = button;
    }

    public void setVisualInterpolationInverse(Interpolation interpolation) {
        this.visualInterpolationInverse = interpolation;
    }

    public void setVisualPercent(float percent) {
        setValue(this.min + ((this.max - this.min) * this.visualInterpolationInverse.apply(percent)));
    }

    /* loaded from: classes.dex */
    public static class SliderStyle extends ProgressBar.ProgressBarStyle {
        public Drawable backgroundDown;
        public Drawable backgroundOver;
        public Drawable knobAfterDown;
        public Drawable knobAfterOver;
        public Drawable knobBeforeDown;
        public Drawable knobBeforeOver;
        public Drawable knobDown;
        public Drawable knobOver;

        public SliderStyle() {
        }

        public SliderStyle(Drawable background, Drawable knob) {
            super(background, knob);
        }

        public SliderStyle(SliderStyle style) {
            super(style);
            this.backgroundOver = style.backgroundOver;
            this.backgroundDown = style.backgroundDown;
            this.knobOver = style.knobOver;
            this.knobDown = style.knobDown;
            this.knobBeforeOver = style.knobBeforeOver;
            this.knobBeforeDown = style.knobBeforeDown;
            this.knobAfterOver = style.knobAfterOver;
            this.knobAfterDown = style.knobAfterDown;
        }
    }
}