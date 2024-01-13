package com.badlogic.gdx.scenes.scene2d.actions;

/* loaded from: classes.dex */
public class ScaleByAction extends RelativeTemporalAction {
    private float amountX;
    private float amountY;

    @Override // com.badlogic.gdx.scenes.scene2d.actions.RelativeTemporalAction
    protected void updateRelative(float percentDelta) {
        this.target.scaleBy(this.amountX * percentDelta, this.amountY * percentDelta);
    }

    public void setAmount(float x, float y) {
        this.amountX = x;
        this.amountY = y;
    }

    public void setAmount(float scale) {
        this.amountX = scale;
        this.amountY = scale;
    }

    public float getAmountX() {
        return this.amountX;
    }

    public void setAmountX(float x) {
        this.amountX = x;
    }

    public float getAmountY() {
        return this.amountY;
    }

    public void setAmountY(float y) {
        this.amountY = y;
    }
}