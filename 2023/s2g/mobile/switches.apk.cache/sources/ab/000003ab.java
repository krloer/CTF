package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Pools;

/* loaded from: classes.dex */
public class ProgressBar extends Widget implements Disableable {
    private float animateDuration;
    private float animateFromValue;
    private Interpolation animateInterpolation;
    private float animateTime;
    boolean disabled;
    float max;
    float min;
    float position;
    private boolean programmaticChangeEvents;
    private boolean round;
    float stepSize;
    private ProgressBarStyle style;
    private float value;
    final boolean vertical;
    private Interpolation visualInterpolation;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public ProgressBar(float r8, float r9, float r10, boolean r11, com.badlogic.gdx.scenes.scene2d.ui.Skin r12) {
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
            java.lang.Class<com.badlogic.gdx.scenes.scene2d.ui.ProgressBar$ProgressBarStyle> r1 = com.badlogic.gdx.scenes.scene2d.ui.ProgressBar.ProgressBarStyle.class
            java.lang.Object r0 = r12.get(r0, r1)
            r6 = r0
            com.badlogic.gdx.scenes.scene2d.ui.ProgressBar$ProgressBarStyle r6 = (com.badlogic.gdx.scenes.scene2d.ui.ProgressBar.ProgressBarStyle) r6
            r1 = r7
            r2 = r8
            r3 = r9
            r4 = r10
            r5 = r11
            r1.<init>(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.scenes.scene2d.ui.ProgressBar.<init>(float, float, float, boolean, com.badlogic.gdx.scenes.scene2d.ui.Skin):void");
    }

    public ProgressBar(float min, float max, float stepSize, boolean vertical, Skin skin, String styleName) {
        this(min, max, stepSize, vertical, (ProgressBarStyle) skin.get(styleName, ProgressBarStyle.class));
    }

    public ProgressBar(float min, float max, float stepSize, boolean vertical, ProgressBarStyle style) {
        this.animateInterpolation = Interpolation.linear;
        this.visualInterpolation = Interpolation.linear;
        this.round = true;
        this.programmaticChangeEvents = true;
        if (min > max) {
            throw new IllegalArgumentException("max must be > min. min,max: " + min + ", " + max);
        } else if (stepSize <= 0.0f) {
            throw new IllegalArgumentException("stepSize must be > 0: " + stepSize);
        } else {
            setStyle(style);
            this.min = min;
            this.max = max;
            this.stepSize = stepSize;
            this.vertical = vertical;
            this.value = min;
            setSize(getPrefWidth(), getPrefHeight());
        }
    }

    public void setStyle(ProgressBarStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        invalidateHierarchy();
    }

    public ProgressBarStyle getStyle() {
        return this.style;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void act(float delta) {
        super.act(delta);
        float f = this.animateTime;
        if (f > 0.0f) {
            this.animateTime = f - delta;
            Stage stage = getStage();
            if (stage == null || !stage.getActionsRequestRendering()) {
                return;
            }
            Gdx.graphics.requestRendering();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        float bgLeftWidth;
        float knobHeightHalf;
        float w;
        float h;
        float bgBottomHeight;
        float bgBottomHeight2;
        float w2;
        float h2;
        ProgressBarStyle style = this.style;
        boolean z = this.disabled;
        Drawable knob = style.knob;
        Drawable currentKnob = getKnobDrawable();
        Drawable bg = getBackgroundDrawable();
        Drawable knobBefore = getKnobBeforeDrawable();
        Drawable knobAfter = getKnobAfterDrawable();
        Color color = getColor();
        float x = getX();
        float y = getY();
        float width = getWidth();
        float height = getHeight();
        float knobHeight = knob == null ? 0.0f : knob.getMinHeight();
        float knobWidth = knob == null ? 0.0f : knob.getMinWidth();
        float percent = getVisualPercent();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        if (this.vertical) {
            float positionHeight = height;
            float bgTopHeight = 0.0f;
            if (bg == null) {
                bgBottomHeight = 0.0f;
            } else {
                if (this.round) {
                    bg.draw(batch, Math.round(((width - bg.getMinWidth()) * 0.5f) + x), y, Math.round(bg.getMinWidth()), height);
                } else {
                    bg.draw(batch, x + ((width - bg.getMinWidth()) * 0.5f), y, bg.getMinWidth(), height);
                }
                bgTopHeight = bg.getTopHeight();
                float bgBottomHeight3 = bg.getBottomHeight();
                positionHeight -= bgTopHeight + bgBottomHeight3;
                bgBottomHeight = bgBottomHeight3;
            }
            if (knob != null) {
                this.position = (positionHeight - knobHeight) * percent;
                this.position = Math.min(positionHeight - knobHeight, this.position) + bgBottomHeight;
                knobHeightHalf = knobHeight * 0.5f;
            } else {
                knobHeightHalf = knobBefore != null ? knobBefore.getMinHeight() * 0.5f : 0.0f;
                float knobHeightHalf2 = knobHeightHalf;
                this.position = (positionHeight - knobHeightHalf2) * percent;
                this.position = Math.min(positionHeight - knobHeightHalf2, this.position);
            }
            this.position = Math.max(bgBottomHeight, this.position);
            if (knobBefore == null) {
                bgBottomHeight2 = bgBottomHeight;
            } else if (this.round) {
                bgBottomHeight2 = bgBottomHeight;
                knobBefore.draw(batch, Math.round(((width - knobBefore.getMinWidth()) * 0.5f) + x), Math.round(y + bgTopHeight), Math.round(knobBefore.getMinWidth()), Math.round(this.position + knobHeightHalf));
            } else {
                bgBottomHeight2 = bgBottomHeight;
                knobBefore.draw(batch, x + ((width - knobBefore.getMinWidth()) * 0.5f), y + bgTopHeight, knobBefore.getMinWidth(), this.position + knobHeightHalf);
            }
            if (knobAfter != null) {
                if (this.round) {
                    knobAfter.draw(batch, Math.round(((width - knobAfter.getMinWidth()) * 0.5f) + x), Math.round(y + this.position + knobHeightHalf), Math.round(knobAfter.getMinWidth()), Math.round(((height - this.position) - knobHeightHalf) - bgBottomHeight2));
                } else {
                    knobAfter.draw(batch, x + ((width - knobAfter.getMinWidth()) * 0.5f), y + this.position + knobHeightHalf, knobAfter.getMinWidth(), ((height - this.position) - knobHeightHalf) - bgBottomHeight2);
                }
            }
            if (currentKnob != null) {
                float w3 = currentKnob.getMinWidth();
                float h3 = currentKnob.getMinHeight();
                float x2 = x + ((width - w3) * 0.5f);
                float y2 = y + ((knobHeight - h3) * 0.5f) + this.position;
                if (!this.round) {
                    w2 = w3;
                    h2 = h3;
                } else {
                    w2 = Math.round(w3);
                    h2 = Math.round(h3);
                    x2 = Math.round(x2);
                    y2 = Math.round(y2);
                }
                currentKnob.draw(batch, x2, y2, w2, h2);
                return;
            }
            return;
        }
        float positionWidth = width;
        float bgRightWidth = 0.0f;
        if (bg == null) {
            bgLeftWidth = 0.0f;
        } else {
            if (this.round) {
                bg.draw(batch, x, Math.round(y + ((height - bg.getMinHeight()) * 0.5f)), width, Math.round(bg.getMinHeight()));
            } else {
                bg.draw(batch, x, y + ((height - bg.getMinHeight()) * 0.5f), width, bg.getMinHeight());
            }
            float bgLeftWidth2 = bg.getLeftWidth();
            bgRightWidth = bg.getRightWidth();
            positionWidth -= bgLeftWidth2 + bgRightWidth;
            bgLeftWidth = bgLeftWidth2;
        }
        if (knob == null) {
            knobHeightHalf = knobBefore != null ? knobBefore.getMinWidth() * 0.5f : 0.0f;
            float knobWidthHalf = knobHeightHalf;
            this.position = (positionWidth - knobWidthHalf) * percent;
            this.position = Math.min(positionWidth - knobWidthHalf, this.position);
        } else {
            float knobWidthHalf2 = knobWidth * 0.5f;
            this.position = (positionWidth - knobWidth) * percent;
            this.position = Math.min(positionWidth - knobWidth, this.position) + bgLeftWidth;
            knobHeightHalf = knobWidthHalf2;
        }
        float knobWidthHalf3 = this.position;
        this.position = Math.max(bgLeftWidth, knobWidthHalf3);
        if (knobBefore != null) {
            if (this.round) {
                knobBefore.draw(batch, Math.round(x + bgLeftWidth), Math.round(y + ((height - knobBefore.getMinHeight()) * 0.5f)), Math.round(this.position + knobHeightHalf), Math.round(knobBefore.getMinHeight()));
            } else {
                knobBefore.draw(batch, x + bgLeftWidth, y + ((height - knobBefore.getMinHeight()) * 0.5f), this.position + knobHeightHalf, knobBefore.getMinHeight());
            }
        }
        if (knobAfter != null) {
            if (this.round) {
                knobAfter.draw(batch, Math.round(this.position + x + knobHeightHalf), Math.round(y + ((height - knobAfter.getMinHeight()) * 0.5f)), Math.round(((width - this.position) - knobHeightHalf) - bgRightWidth), Math.round(knobAfter.getMinHeight()));
            } else {
                knobAfter.draw(batch, this.position + x + knobHeightHalf, y + ((height - knobAfter.getMinHeight()) * 0.5f), ((width - this.position) - knobHeightHalf) - bgRightWidth, knobAfter.getMinHeight());
            }
        }
        if (currentKnob != null) {
            float w4 = currentKnob.getMinWidth();
            float h4 = currentKnob.getMinHeight();
            float x3 = x + ((knobWidth - w4) * 0.5f) + this.position;
            float y3 = y + ((height - h4) * 0.5f);
            if (!this.round) {
                w = w4;
                h = h4;
            } else {
                w = Math.round(w4);
                h = Math.round(h4);
                x3 = Math.round(x3);
                y3 = Math.round(y3);
            }
            currentKnob.draw(batch, x3, y3, w, h);
        }
    }

    public float getValue() {
        return this.value;
    }

    public float getVisualValue() {
        float f = this.animateTime;
        return f > 0.0f ? this.animateInterpolation.apply(this.animateFromValue, this.value, 1.0f - (f / this.animateDuration)) : this.value;
    }

    public void updateVisualValue() {
        this.animateTime = 0.0f;
    }

    public float getPercent() {
        float f = this.min;
        float f2 = this.max;
        if (f == f2) {
            return 0.0f;
        }
        return (this.value - f) / (f2 - f);
    }

    public float getVisualPercent() {
        if (this.min == this.max) {
            return 0.0f;
        }
        Interpolation interpolation = this.visualInterpolation;
        float visualValue = getVisualValue();
        float f = this.min;
        return interpolation.apply((visualValue - f) / (this.max - f));
    }

    protected Drawable getBackgroundDrawable() {
        return (!this.disabled || this.style.disabledBackground == null) ? this.style.background : this.style.disabledBackground;
    }

    protected Drawable getKnobDrawable() {
        return (!this.disabled || this.style.disabledKnob == null) ? this.style.knob : this.style.disabledKnob;
    }

    protected Drawable getKnobBeforeDrawable() {
        return (!this.disabled || this.style.disabledKnobBefore == null) ? this.style.knobBefore : this.style.disabledKnobBefore;
    }

    protected Drawable getKnobAfterDrawable() {
        return (!this.disabled || this.style.disabledKnobAfter == null) ? this.style.knobAfter : this.style.disabledKnobAfter;
    }

    protected float getKnobPosition() {
        return this.position;
    }

    public boolean setValue(float value) {
        float value2 = clamp(round(value));
        float oldValue = this.value;
        if (value2 == oldValue) {
            return false;
        }
        float oldVisualValue = getVisualValue();
        this.value = value2;
        if (this.programmaticChangeEvents) {
            ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
            boolean cancelled = fire(changeEvent);
            Pools.free(changeEvent);
            if (cancelled) {
                this.value = oldValue;
                return false;
            }
        }
        float f = this.animateDuration;
        if (f > 0.0f) {
            this.animateFromValue = oldVisualValue;
            this.animateTime = f;
            return true;
        }
        return true;
    }

    protected float round(float value) {
        return Math.round(value / this.stepSize) * this.stepSize;
    }

    protected float clamp(float value) {
        return MathUtils.clamp(value, this.min, this.max);
    }

    public void setRange(float min, float max) {
        if (min > max) {
            throw new IllegalArgumentException("min must be <= max: " + min + " <= " + max);
        }
        this.min = min;
        this.max = max;
        float f = this.value;
        if (f < min) {
            setValue(min);
        } else if (f > max) {
            setValue(max);
        }
    }

    public void setStepSize(float stepSize) {
        if (stepSize <= 0.0f) {
            throw new IllegalArgumentException("steps must be > 0: " + stepSize);
        }
        this.stepSize = stepSize;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        if (this.vertical) {
            Drawable knob = this.style.knob;
            Drawable bg = getBackgroundDrawable();
            return Math.max(knob == null ? 0.0f : knob.getMinWidth(), bg != null ? bg.getMinWidth() : 0.0f);
        }
        return 140.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        if (this.vertical) {
            return 140.0f;
        }
        Drawable knob = this.style.knob;
        Drawable bg = getBackgroundDrawable();
        return Math.max(knob == null ? 0.0f : knob.getMinHeight(), bg != null ? bg.getMinHeight() : 0.0f);
    }

    public float getMinValue() {
        return this.min;
    }

    public float getMaxValue() {
        return this.max;
    }

    public float getStepSize() {
        return this.stepSize;
    }

    public void setAnimateDuration(float duration) {
        this.animateDuration = duration;
    }

    public void setAnimateInterpolation(Interpolation animateInterpolation) {
        if (animateInterpolation == null) {
            throw new IllegalArgumentException("animateInterpolation cannot be null.");
        }
        this.animateInterpolation = animateInterpolation;
    }

    public void setVisualInterpolation(Interpolation interpolation) {
        this.visualInterpolation = interpolation;
    }

    public void setRound(boolean round) {
        this.round = round;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public boolean isAnimating() {
        return this.animateTime > 0.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public boolean isDisabled() {
        return this.disabled;
    }

    public boolean isVertical() {
        return this.vertical;
    }

    public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
        this.programmaticChangeEvents = programmaticChangeEvents;
    }

    /* loaded from: classes.dex */
    public static class ProgressBarStyle {
        public Drawable background;
        public Drawable disabledBackground;
        public Drawable disabledKnob;
        public Drawable disabledKnobAfter;
        public Drawable disabledKnobBefore;
        public Drawable knob;
        public Drawable knobAfter;
        public Drawable knobBefore;

        public ProgressBarStyle() {
        }

        public ProgressBarStyle(Drawable background, Drawable knob) {
            this.background = background;
            this.knob = knob;
        }

        public ProgressBarStyle(ProgressBarStyle style) {
            this.background = style.background;
            this.disabledBackground = style.disabledBackground;
            this.knob = style.knob;
            this.disabledKnob = style.disabledKnob;
            this.knobBefore = style.knobBefore;
            this.disabledKnobBefore = style.disabledKnobBefore;
            this.knobAfter = style.knobAfter;
            this.disabledKnobAfter = style.disabledKnobAfter;
        }
    }
}