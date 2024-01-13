package com.badlogic.gdx.graphics.g3d.particles.renderers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;
import com.badlogic.gdx.graphics.g3d.particles.batches.PointSpriteParticleBatch;

/* loaded from: classes.dex */
public class PointSpriteRenderer extends ParticleControllerRenderer<PointSpriteControllerRenderData, PointSpriteParticleBatch> {
    public PointSpriteRenderer() {
        super(new PointSpriteControllerRenderData());
    }

    public PointSpriteRenderer(PointSpriteParticleBatch batch) {
        this();
        setBatch(batch);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        ((PointSpriteControllerRenderData) this.renderData).positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
        ((PointSpriteControllerRenderData) this.renderData).regionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.TextureRegion, ParticleChannels.TextureRegionInitializer.get());
        ((PointSpriteControllerRenderData) this.renderData).colorChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Color, ParticleChannels.ColorInitializer.get());
        ((PointSpriteControllerRenderData) this.renderData).scaleChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Scale, ParticleChannels.ScaleInitializer.get());
        ((PointSpriteControllerRenderData) this.renderData).rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation2D, ParticleChannels.Rotation2dInitializer.get());
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderer
    public boolean isCompatible(ParticleBatch<?> batch) {
        return batch instanceof PointSpriteParticleBatch;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public ParticleControllerComponent copy() {
        return new PointSpriteRenderer((PointSpriteParticleBatch) this.batch);
    }
}