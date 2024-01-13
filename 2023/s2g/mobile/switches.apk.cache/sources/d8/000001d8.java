package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleController;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;
import java.util.Arrays;

/* loaded from: classes.dex */
public class DynamicsInfluencer extends Influencer {
    private ParallelArray.FloatChannel accellerationChannel;
    private ParallelArray.FloatChannel angularVelocityChannel;
    boolean has2dAngularVelocity;
    boolean has3dAngularVelocity;
    boolean hasAcceleration;
    private ParallelArray.FloatChannel positionChannel;
    private ParallelArray.FloatChannel previousPositionChannel;
    private ParallelArray.FloatChannel rotationChannel;
    public Array<DynamicsModifier> velocities;

    public DynamicsInfluencer() {
        this.velocities = new Array<>(true, 3, DynamicsModifier.class);
    }

    public DynamicsInfluencer(DynamicsModifier... velocities) {
        this.velocities = new Array<>(true, velocities.length, DynamicsModifier.class);
        for (DynamicsModifier value : velocities) {
            this.velocities.add((DynamicsModifier) value.copy());
        }
    }

    public DynamicsInfluencer(DynamicsInfluencer velocityInfluencer) {
        this((DynamicsModifier[]) velocityInfluencer.velocities.toArray(DynamicsModifier.class));
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        for (int k = 0; k < this.velocities.size; k++) {
            this.velocities.items[k].allocateChannels();
        }
        this.accellerationChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.Acceleration);
        this.hasAcceleration = this.accellerationChannel != null;
        if (this.hasAcceleration) {
            this.positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
            this.previousPositionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.PreviousPosition);
        }
        this.angularVelocityChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.AngularVelocity2D);
        this.has2dAngularVelocity = this.angularVelocityChannel != null;
        if (this.has2dAngularVelocity) {
            this.rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation2D);
            this.has3dAngularVelocity = false;
            return;
        }
        this.angularVelocityChannel = (ParallelArray.FloatChannel) this.controller.particles.getChannel(ParticleChannels.AngularVelocity3D);
        this.has3dAngularVelocity = this.angularVelocityChannel != null;
        if (this.has3dAngularVelocity) {
            this.rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation3D);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void set(ParticleController particleController) {
        super.set(particleController);
        for (int k = 0; k < this.velocities.size; k++) {
            this.velocities.items[k].set(particleController);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void init() {
        for (int k = 0; k < this.velocities.size; k++) {
            this.velocities.items[k].init();
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void activateParticles(int startIndex, int count) {
        if (this.hasAcceleration) {
            int i = this.positionChannel.strideSize * startIndex;
            int c = (this.positionChannel.strideSize * count) + i;
            while (i < c) {
                this.previousPositionChannel.data[i + 0] = this.positionChannel.data[i + 0];
                this.previousPositionChannel.data[i + 1] = this.positionChannel.data[i + 1];
                this.previousPositionChannel.data[i + 2] = this.positionChannel.data[i + 2];
                i += this.positionChannel.strideSize;
            }
        }
        if (this.has2dAngularVelocity) {
            int i2 = this.rotationChannel.strideSize * startIndex;
            int c2 = (this.rotationChannel.strideSize * count) + i2;
            while (i2 < c2) {
                this.rotationChannel.data[i2 + 0] = 1.0f;
                this.rotationChannel.data[i2 + 1] = 0.0f;
                i2 += this.rotationChannel.strideSize;
            }
        } else if (this.has3dAngularVelocity) {
            int i3 = this.rotationChannel.strideSize * startIndex;
            int c3 = (this.rotationChannel.strideSize * count) + i3;
            while (i3 < c3) {
                this.rotationChannel.data[i3 + 0] = 0.0f;
                this.rotationChannel.data[i3 + 1] = 0.0f;
                this.rotationChannel.data[i3 + 2] = 0.0f;
                this.rotationChannel.data[i3 + 3] = 1.0f;
                i3 += this.rotationChannel.strideSize;
            }
        }
        for (int k = 0; k < this.velocities.size; k++) {
            this.velocities.items[k].activateParticles(startIndex, count);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void update() {
        if (this.hasAcceleration) {
            Arrays.fill(this.accellerationChannel.data, 0, this.controller.particles.size * this.accellerationChannel.strideSize, 0.0f);
        }
        if (this.has2dAngularVelocity || this.has3dAngularVelocity) {
            Arrays.fill(this.angularVelocityChannel.data, 0, this.controller.particles.size * this.angularVelocityChannel.strideSize, 0.0f);
        }
        for (int k = 0; k < this.velocities.size; k++) {
            this.velocities.items[k].update();
        }
        if (this.hasAcceleration) {
            int i = 0;
            int offset = 0;
            while (i < this.controller.particles.size) {
                float x = this.positionChannel.data[offset + 0];
                float y = this.positionChannel.data[offset + 1];
                float z = this.positionChannel.data[offset + 2];
                this.positionChannel.data[offset + 0] = ((x * 2.0f) - this.previousPositionChannel.data[offset + 0]) + (this.accellerationChannel.data[offset + 0] * this.controller.deltaTimeSqr);
                this.positionChannel.data[offset + 1] = ((y * 2.0f) - this.previousPositionChannel.data[offset + 1]) + (this.accellerationChannel.data[offset + 1] * this.controller.deltaTimeSqr);
                this.positionChannel.data[offset + 2] = ((2.0f * z) - this.previousPositionChannel.data[offset + 2]) + (this.accellerationChannel.data[offset + 2] * this.controller.deltaTimeSqr);
                this.previousPositionChannel.data[offset + 0] = x;
                this.previousPositionChannel.data[offset + 1] = y;
                this.previousPositionChannel.data[offset + 2] = z;
                i++;
                offset += this.positionChannel.strideSize;
            }
        }
        if (this.has2dAngularVelocity) {
            int i2 = 0;
            int offset2 = 0;
            while (i2 < this.controller.particles.size) {
                float rotation = this.angularVelocityChannel.data[i2] * this.controller.deltaTime;
                if (rotation != 0.0f) {
                    float cosBeta = MathUtils.cosDeg(rotation);
                    float sinBeta = MathUtils.sinDeg(rotation);
                    float currentCosine = this.rotationChannel.data[offset2 + 0];
                    float currentSine = this.rotationChannel.data[offset2 + 1];
                    float newCosine = (currentCosine * cosBeta) - (currentSine * sinBeta);
                    float newSine = (currentSine * cosBeta) + (currentCosine * sinBeta);
                    this.rotationChannel.data[offset2 + 0] = newCosine;
                    this.rotationChannel.data[offset2 + 1] = newSine;
                }
                i2++;
                offset2 += this.rotationChannel.strideSize;
            }
        } else if (this.has3dAngularVelocity) {
            int i3 = 0;
            int offset3 = 0;
            int angularOffset = 0;
            while (i3 < this.controller.particles.size) {
                float wx = this.angularVelocityChannel.data[angularOffset + 0];
                float wy = this.angularVelocityChannel.data[angularOffset + 1];
                float wz = this.angularVelocityChannel.data[angularOffset + 2];
                float qx = this.rotationChannel.data[offset3 + 0];
                float qy = this.rotationChannel.data[offset3 + 1];
                float qz = this.rotationChannel.data[offset3 + 2];
                float qw = this.rotationChannel.data[offset3 + 3];
                TMP_Q.set(wx, wy, wz, 0.0f).mul(qx, qy, qz, qw).mul(this.controller.deltaTime * 0.5f).add(qx, qy, qz, qw).nor();
                this.rotationChannel.data[offset3 + 0] = TMP_Q.x;
                this.rotationChannel.data[offset3 + 1] = TMP_Q.y;
                this.rotationChannel.data[offset3 + 2] = TMP_Q.z;
                this.rotationChannel.data[offset3 + 3] = TMP_Q.w;
                i3++;
                offset3 += this.rotationChannel.strideSize;
                angularOffset += this.angularVelocityChannel.strideSize;
            }
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public DynamicsInfluencer copy() {
        return new DynamicsInfluencer(this);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        json.writeValue("velocities", this.velocities, Array.class, DynamicsModifier.class);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        this.velocities.addAll((Array) json.readValue("velocities", (Class<Object>) Array.class, DynamicsModifier.class, jsonData));
    }
}