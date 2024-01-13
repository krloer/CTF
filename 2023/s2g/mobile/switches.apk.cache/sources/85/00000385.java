package com.badlogic.gdx.scenes.scene2d.actions;

import com.badlogic.gdx.math.MathUtils;

/* loaded from: classes.dex */
public class RotateToAction extends TemporalAction {
    private float end;
    private float start;
    private boolean useShortestDirection;

    public RotateToAction() {
        this.useShortestDirection = false;
    }

    public RotateToAction(boolean useShortestDirection) {
        this.useShortestDirection = false;
        this.useShortestDirection = useShortestDirection;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void begin() {
        this.start = this.target.getRotation();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.actions.TemporalAction
    protected void update(float percent) {
        float rotation;
        if (percent == 0.0f) {
            rotation = this.start;
        } else if (percent == 1.0f) {
            rotation = this.end;
        } else if (this.useShortestDirection) {
            rotation = MathUtils.lerpAngleDeg(this.start, this.end, percent);
        } else {
            float rotation2 = this.start;
            rotation = rotation2 + ((this.end - rotation2) * percent);
        }
        this.target.setRotation(rotation);
    }

    public float getRotation() {
        return this.end;
    }

    public void setRotation(float rotation) {
        this.end = rotation;
    }

    public boolean isUseShortestDirection() {
        return this.useShortestDirection;
    }

    public void setUseShortestDirection(boolean useShortestDirection) {
        this.useShortestDirection = useShortestDirection;
    }
}