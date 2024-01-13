package com.badlogic.gdx.graphics.g3d.particles.renderers;

import com.badlogic.gdx.graphics.g3d.particles.ParticleController;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;
import com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderData;

/* loaded from: classes.dex */
public abstract class ParticleControllerRenderer<D extends ParticleControllerRenderData, T extends ParticleBatch<D>> extends ParticleControllerComponent {
    protected T batch;
    protected D renderData;

    public abstract boolean isCompatible(ParticleBatch<?> particleBatch);

    /* JADX INFO: Access modifiers changed from: protected */
    public ParticleControllerRenderer() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ParticleControllerRenderer(D renderData) {
        this.renderData = renderData;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void update() {
        this.batch.draw(this.renderData);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean setBatch(ParticleBatch<?> batch) {
        if (isCompatible(batch)) {
            this.batch = batch;
            return true;
        }
        return false;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void set(ParticleController particleController) {
        super.set(particleController);
        D d = this.renderData;
        if (d != null) {
            d.controller = this.controller;
        }
    }
}