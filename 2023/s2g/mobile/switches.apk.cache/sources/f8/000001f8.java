package com.badlogic.gdx.graphics.g3d.particles.renderers;

import com.badlogic.gdx.graphics.g3d.ModelInstance;
import com.badlogic.gdx.graphics.g3d.attributes.BlendingAttribute;
import com.badlogic.gdx.graphics.g3d.attributes.ColorAttribute;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;
import com.badlogic.gdx.graphics.g3d.particles.batches.ModelInstanceParticleBatch;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;

/* loaded from: classes.dex */
public class ModelInstanceRenderer extends ParticleControllerRenderer<ModelInstanceControllerRenderData, ModelInstanceParticleBatch> {
    private boolean hasColor;
    private boolean hasRotation;
    private boolean hasScale;

    public ModelInstanceRenderer() {
        super(new ModelInstanceControllerRenderData());
    }

    public ModelInstanceRenderer(ModelInstanceParticleBatch batch) {
        this();
        setBatch(batch);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        ((ModelInstanceControllerRenderData) this.renderData).positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void init() {
        ((ModelInstanceControllerRenderData) this.renderData).modelInstanceChannel = (ParallelArray.ObjectChannel) this.controller.particles.getChannel(ParticleChannels.ModelInstance);
        ((ModelInstanceControllerRenderData) this.renderData).colorChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Color);
        ((ModelInstanceControllerRenderData) this.renderData).scaleChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Scale);
        ((ModelInstanceControllerRenderData) this.renderData).rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Rotation3D);
        this.hasColor = ((ModelInstanceControllerRenderData) this.renderData).colorChannel != null;
        this.hasScale = ((ModelInstanceControllerRenderData) this.renderData).scaleChannel != null;
        this.hasRotation = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel != null;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderer, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void update() {
        float qy;
        float qz;
        float qw;
        int i = 0;
        int positionOffset = 0;
        int c = this.controller.particles.size;
        while (i < c) {
            ModelInstance instance = ((ModelInstanceControllerRenderData) this.renderData).modelInstanceChannel.data[i];
            float scale = this.hasScale ? ((ModelInstanceControllerRenderData) this.renderData).scaleChannel.data[i] : 1.0f;
            float qx = 0.0f;
            if (!this.hasRotation) {
                qy = 0.0f;
                qz = 0.0f;
                qw = 1.0f;
            } else {
                int rotationOffset = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel.strideSize * i;
                qx = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel.data[rotationOffset + 0];
                float qy2 = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel.data[rotationOffset + 1];
                float qz2 = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel.data[rotationOffset + 2];
                float qw2 = ((ModelInstanceControllerRenderData) this.renderData).rotationChannel.data[rotationOffset + 3];
                qy = qy2;
                qz = qz2;
                qw = qw2;
            }
            instance.transform.set(((ModelInstanceControllerRenderData) this.renderData).positionChannel.data[positionOffset + 0], ((ModelInstanceControllerRenderData) this.renderData).positionChannel.data[positionOffset + 1], ((ModelInstanceControllerRenderData) this.renderData).positionChannel.data[positionOffset + 2], qx, qy, qz, qw, scale, scale, scale);
            if (this.hasColor) {
                int colorOffset = ((ModelInstanceControllerRenderData) this.renderData).colorChannel.strideSize * i;
                ColorAttribute colorAttribute = (ColorAttribute) instance.materials.get(0).get(ColorAttribute.Diffuse);
                BlendingAttribute blendingAttribute = (BlendingAttribute) instance.materials.get(0).get(BlendingAttribute.Type);
                colorAttribute.color.r = ((ModelInstanceControllerRenderData) this.renderData).colorChannel.data[colorOffset + 0];
                colorAttribute.color.g = ((ModelInstanceControllerRenderData) this.renderData).colorChannel.data[colorOffset + 1];
                colorAttribute.color.b = ((ModelInstanceControllerRenderData) this.renderData).colorChannel.data[colorOffset + 2];
                if (blendingAttribute != null) {
                    blendingAttribute.opacity = ((ModelInstanceControllerRenderData) this.renderData).colorChannel.data[colorOffset + 3];
                }
            }
            i++;
            positionOffset += ((ModelInstanceControllerRenderData) this.renderData).positionChannel.strideSize;
        }
        super.update();
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public ParticleControllerComponent copy() {
        return new ModelInstanceRenderer((ModelInstanceParticleBatch) this.batch);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderer
    public boolean isCompatible(ParticleBatch<?> batch) {
        return batch instanceof ModelInstanceParticleBatch;
    }
}