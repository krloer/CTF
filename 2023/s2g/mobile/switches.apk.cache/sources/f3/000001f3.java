package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.values.ScaledNumericValue;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public abstract class SimpleInfluencer extends Influencer {
    ParallelArray.FloatChannel interpolationChannel;
    ParallelArray.FloatChannel lifeChannel;
    public ScaledNumericValue value;
    ParallelArray.FloatChannel valueChannel;
    ParallelArray.ChannelDescriptor valueChannelDescriptor;

    public SimpleInfluencer() {
        this.value = new ScaledNumericValue();
        this.value.setHigh(1.0f);
    }

    public SimpleInfluencer(SimpleInfluencer billboardScaleinfluencer) {
        this();
        set(billboardScaleinfluencer);
    }

    private void set(SimpleInfluencer scaleInfluencer) {
        this.value.load(scaleInfluencer.value);
        this.valueChannelDescriptor = scaleInfluencer.valueChannelDescriptor;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.valueChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(this.valueChannelDescriptor);
        ParticleChannels.Interpolation.id = this.controller.particleChannels.newId();
        this.interpolationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Interpolation);
        this.lifeChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Life);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void activateParticles(int startIndex, int count) {
        if (!this.value.isRelative()) {
            int i = this.valueChannel.strideSize * startIndex;
            int a = this.interpolationChannel.strideSize * startIndex;
            int c = (this.valueChannel.strideSize * count) + i;
            while (i < c) {
                float start = this.value.newLowValue();
                float diff = this.value.newHighValue() - start;
                this.interpolationChannel.data[a + 0] = start;
                this.interpolationChannel.data[a + 1] = diff;
                this.valueChannel.data[i] = (this.value.getScale(0.0f) * diff) + start;
                i += this.valueChannel.strideSize;
                a += this.interpolationChannel.strideSize;
            }
            return;
        }
        int i2 = this.valueChannel.strideSize * startIndex;
        int a2 = this.interpolationChannel.strideSize * startIndex;
        int c2 = (this.valueChannel.strideSize * count) + i2;
        while (i2 < c2) {
            float start2 = this.value.newLowValue();
            float diff2 = this.value.newHighValue();
            this.interpolationChannel.data[a2 + 0] = start2;
            this.interpolationChannel.data[a2 + 1] = diff2;
            this.valueChannel.data[i2] = (this.value.getScale(0.0f) * diff2) + start2;
            i2 += this.valueChannel.strideSize;
            a2 += this.interpolationChannel.strideSize;
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void update() {
        int i = 0;
        int a = 0;
        int l = 2;
        int c = (this.controller.particles.size * this.valueChannel.strideSize) + 0;
        while (i < c) {
            this.valueChannel.data[i] = this.interpolationChannel.data[a + 0] + (this.interpolationChannel.data[a + 1] * this.value.getScale(this.lifeChannel.data[l]));
            i += this.valueChannel.strideSize;
            a += this.interpolationChannel.strideSize;
            l += this.lifeChannel.strideSize;
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        json.writeValue("value", this.value);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        this.value = (ScaledNumericValue) json.readValue("value", ScaledNumericValue.class, jsonData);
    }
}