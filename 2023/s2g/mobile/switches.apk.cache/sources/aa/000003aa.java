package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.ParticleEffect;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.utils.Disposable;

/* loaded from: classes.dex */
public class ParticleEffectActor extends Actor implements Disposable {
    private boolean autoRemove;
    protected boolean isRunning;
    protected float lastDelta;
    protected boolean ownsEffect;
    private final ParticleEffect particleEffect;
    private boolean resetOnStart;

    public ParticleEffectActor(ParticleEffect particleEffect, boolean resetOnStart) {
        this.particleEffect = particleEffect;
        this.resetOnStart = resetOnStart;
    }

    public ParticleEffectActor(FileHandle particleFile, TextureAtlas atlas) {
        this.particleEffect = new ParticleEffect();
        this.particleEffect.load(particleFile, atlas);
        this.ownsEffect = true;
    }

    public ParticleEffectActor(FileHandle particleFile, FileHandle imagesDir) {
        this.particleEffect = new ParticleEffect();
        this.particleEffect.load(particleFile, imagesDir);
        this.ownsEffect = true;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        this.particleEffect.setPosition(getX(), getY());
        float f = this.lastDelta;
        if (f > 0.0f) {
            this.particleEffect.update(f);
            this.lastDelta = 0.0f;
        }
        if (this.isRunning) {
            this.particleEffect.draw(batch);
            this.isRunning = !this.particleEffect.isComplete();
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void act(float delta) {
        super.act(delta);
        this.lastDelta += delta;
        if (this.autoRemove && this.particleEffect.isComplete()) {
            remove();
        }
    }

    public void start() {
        this.isRunning = true;
        if (this.resetOnStart) {
            this.particleEffect.reset(false);
        }
        this.particleEffect.start();
    }

    public boolean isResetOnStart() {
        return this.resetOnStart;
    }

    public ParticleEffectActor setResetOnStart(boolean resetOnStart) {
        this.resetOnStart = resetOnStart;
        return this;
    }

    public boolean isAutoRemove() {
        return this.autoRemove;
    }

    public ParticleEffectActor setAutoRemove(boolean autoRemove) {
        this.autoRemove = autoRemove;
        return this;
    }

    public boolean isRunning() {
        return this.isRunning;
    }

    public ParticleEffect getEffect() {
        return this.particleEffect;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void scaleChanged() {
        super.scaleChanged();
        this.particleEffect.scaleEffect(getScaleX(), getScaleY(), getScaleY());
    }

    public void cancel() {
        this.isRunning = true;
    }

    public void allowCompletion() {
        this.particleEffect.allowCompletion();
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.ownsEffect) {
            this.particleEffect.dispose();
        }
    }
}