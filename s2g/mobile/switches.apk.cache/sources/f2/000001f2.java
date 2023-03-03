package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;

/* loaded from: classes.dex */
public class ScaleInfluencer extends SimpleInfluencer {
    public ScaleInfluencer() {
        this.valueChannelDescriptor = ParticleChannels.Scale;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.SimpleInfluencer, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void activateParticles(int startIndex, int count) {
        if (this.value.isRelative()) {
            int i = this.valueChannel.strideSize * startIndex;
            int a = this.interpolationChannel.strideSize * startIndex;
            int c = (this.valueChannel.strideSize * count) + i;
            while (i < c) {
                float start = this.value.newLowValue() * this.controller.scale.x;
                float diff = this.value.newHighValue() * this.controller.scale.x;
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
            float start2 = this.value.newLowValue() * this.controller.scale.x;
            float diff2 = (this.value.newHighValue() * this.controller.scale.x) - start2;
            this.interpolationChannel.data[a2 + 0] = start2;
            this.interpolationChannel.data[a2 + 1] = diff2;
            this.valueChannel.data[i2] = (this.value.getScale(0.0f) * diff2) + start2;
            i2 += this.valueChannel.strideSize;
            a2 += this.interpolationChannel.strideSize;
        }
    }

    public ScaleInfluencer(ScaleInfluencer scaleInfluencer) {
        super(scaleInfluencer);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public ParticleControllerComponent copy() {
        return new ScaleInfluencer(this);
    }
}