package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleController;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class ParticleControllerFinalizerInfluencer extends Influencer {
    ParallelArray.ObjectChannel<ParticleController> controllerChannel;
    boolean hasRotation;
    boolean hasScale;
    ParallelArray.FloatChannel positionChannel;
    ParallelArray.FloatChannel rotationChannel;
    ParallelArray.FloatChannel scaleChannel;

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void init() {
        this.controllerChannel = (ParallelArray.ObjectChannel) this.controller.particles.getChannel(ParticleChannels.ParticleController);
        if (this.controllerChannel == null) {
            throw new GdxRuntimeException("ParticleController channel not found, specify an influencer which will allocate it please.");
        }
        this.scaleChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Scale);
        this.rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Rotation3D);
        this.hasScale = this.scaleChannel != null;
        this.hasRotation = this.rotationChannel != null;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void update() {
        int i = 0;
        int positionOffset = 0;
        int c = this.controller.particles.size;
        while (i < c) {
            ParticleController particleController = this.controllerChannel.data[i];
            float scale = this.hasScale ? this.scaleChannel.data[i] : 1.0f;
            float qx = 0.0f;
            float qy = 0.0f;
            float qz = 0.0f;
            float qw = 1.0f;
            if (this.hasRotation) {
                int rotationOffset = this.rotationChannel.strideSize * i;
                qx = this.rotationChannel.data[rotationOffset + 0];
                qy = this.rotationChannel.data[rotationOffset + 1];
                qz = this.rotationChannel.data[rotationOffset + 2];
                qw = this.rotationChannel.data[rotationOffset + 3];
            }
            particleController.setTransform(this.positionChannel.data[positionOffset + 0], this.positionChannel.data[positionOffset + 1], this.positionChannel.data[positionOffset + 2], qx, qy, qz, qw, scale);
            particleController.update();
            i++;
            positionOffset += this.positionChannel.strideSize;
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public ParticleControllerFinalizerInfluencer copy() {
        return new ParticleControllerFinalizerInfluencer();
    }
}