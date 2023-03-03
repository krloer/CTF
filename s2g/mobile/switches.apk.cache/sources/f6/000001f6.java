package com.badlogic.gdx.graphics.g3d.particles.renderers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;
import com.badlogic.gdx.graphics.g3d.particles.batches.BillboardParticleBatch;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;

/* loaded from: classes.dex */
public class BillboardRenderer extends ParticleControllerRenderer<BillboardControllerRenderData, BillboardParticleBatch> {
    public BillboardRenderer() {
        super(new BillboardControllerRenderData());
    }

    public BillboardRenderer(BillboardParticleBatch batch) {
        this();
        setBatch(batch);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        ((BillboardControllerRenderData) this.renderData).positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
        ((BillboardControllerRenderData) this.renderData).regionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.TextureRegion, ParticleChannels.TextureRegionInitializer.get());
        ((BillboardControllerRenderData) this.renderData).colorChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Color, ParticleChannels.ColorInitializer.get());
        ((BillboardControllerRenderData) this.renderData).scaleChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Scale, ParticleChannels.ScaleInitializer.get());
        ((BillboardControllerRenderData) this.renderData).rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation2D, ParticleChannels.Rotation2dInitializer.get());
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public ParticleControllerComponent copy() {
        return new BillboardRenderer((BillboardParticleBatch) this.batch);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderer
    public boolean isCompatible(ParticleBatch<?> batch) {
        return batch instanceof BillboardParticleBatch;
    }
}