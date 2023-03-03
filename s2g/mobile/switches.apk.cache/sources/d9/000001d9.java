package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent;
import com.badlogic.gdx.graphics.g3d.particles.values.ScaledNumericValue;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Quaternion;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public abstract class DynamicsModifier extends Influencer {
    public boolean isGlobal;
    protected ParallelArray.FloatChannel lifeChannel;
    protected static final Vector3 TMP_V1 = new Vector3();
    protected static final Vector3 TMP_V2 = new Vector3();
    protected static final Vector3 TMP_V3 = new Vector3();
    protected static final Quaternion TMP_Q = new Quaternion();

    /* loaded from: classes.dex */
    public static class FaceDirection extends DynamicsModifier {
        ParallelArray.FloatChannel accellerationChannel;
        ParallelArray.FloatChannel rotationChannel;

        public FaceDirection() {
        }

        public FaceDirection(FaceDirection rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            this.rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation3D);
            this.accellerationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Acceleration);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int accelOffset = 0;
            for (int c = (this.controller.particles.size * this.rotationChannel.strideSize) + 0; i < c; c = c) {
                Vector3 axisZ = TMP_V1.set(this.accellerationChannel.data[accelOffset + 0], this.accellerationChannel.data[accelOffset + 1], this.accellerationChannel.data[accelOffset + 2]).nor();
                Vector3 axisY = TMP_V2.set(TMP_V1).crs(Vector3.Y).nor().crs(TMP_V1).nor();
                Vector3 axisX = TMP_V3.set(axisY).crs(axisZ).nor();
                TMP_Q.setFromAxes(false, axisX.x, axisY.x, axisZ.x, axisX.y, axisY.y, axisZ.y, axisX.z, axisY.z, axisZ.z);
                this.rotationChannel.data[i + 0] = TMP_Q.x;
                this.rotationChannel.data[i + 1] = TMP_Q.y;
                this.rotationChannel.data[i + 2] = TMP_Q.z;
                this.rotationChannel.data[i + 3] = TMP_Q.w;
                i += this.rotationChannel.strideSize;
                accelOffset += this.accellerationChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public ParticleControllerComponent copy() {
            return new FaceDirection(this);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class Strength extends DynamicsModifier {
        protected ParallelArray.FloatChannel strengthChannel;
        public ScaledNumericValue strengthValue;

        public Strength() {
            this.strengthValue = new ScaledNumericValue();
        }

        public Strength(Strength rotation) {
            super(rotation);
            this.strengthValue = new ScaledNumericValue();
            this.strengthValue.load(rotation.strengthValue);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            ParticleChannels.Interpolation.id = this.controller.particleChannels.newId();
            this.strengthChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Interpolation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            int i = this.strengthChannel.strideSize * startIndex;
            int c = (this.strengthChannel.strideSize * count) + i;
            while (i < c) {
                float start = this.strengthValue.newLowValue();
                float diff = this.strengthValue.newHighValue();
                if (!this.strengthValue.isRelative()) {
                    diff -= start;
                }
                this.strengthChannel.data[i + 0] = start;
                this.strengthChannel.data[i + 1] = diff;
                i += this.strengthChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
        public void write(Json json) {
            super.write(json);
            json.writeValue("strengthValue", this.strengthValue);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
        public void read(Json json, JsonValue jsonData) {
            super.read(json, jsonData);
            this.strengthValue = (ScaledNumericValue) json.readValue("strengthValue", ScaledNumericValue.class, jsonData);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class Angular extends Strength {
        protected ParallelArray.FloatChannel angularChannel;
        public ScaledNumericValue phiValue;
        public ScaledNumericValue thetaValue;

        public Angular() {
            this.thetaValue = new ScaledNumericValue();
            this.phiValue = new ScaledNumericValue();
        }

        public Angular(Angular value) {
            super(value);
            this.thetaValue = new ScaledNumericValue();
            this.phiValue = new ScaledNumericValue();
            this.thetaValue.load(value.thetaValue);
            this.phiValue.load(value.phiValue);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            ParticleChannels.Interpolation4.id = this.controller.particleChannels.newId();
            this.angularChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Interpolation4);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            super.activateParticles(startIndex, count);
            int i = this.angularChannel.strideSize * startIndex;
            int c = (this.angularChannel.strideSize * count) + i;
            while (i < c) {
                float start = this.thetaValue.newLowValue();
                float diff = this.thetaValue.newHighValue();
                if (!this.thetaValue.isRelative()) {
                    diff -= start;
                }
                this.angularChannel.data[i + 0] = start;
                this.angularChannel.data[i + 1] = diff;
                float start2 = this.phiValue.newLowValue();
                float diff2 = this.phiValue.newHighValue();
                if (!this.phiValue.isRelative()) {
                    diff2 -= start2;
                }
                this.angularChannel.data[i + 2] = start2;
                this.angularChannel.data[i + 3] = diff2;
                i += this.angularChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
        public void write(Json json) {
            super.write(json);
            json.writeValue("thetaValue", this.thetaValue);
            json.writeValue("phiValue", this.phiValue);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
        public void read(Json json, JsonValue jsonData) {
            super.read(json, jsonData);
            this.thetaValue = (ScaledNumericValue) json.readValue("thetaValue", ScaledNumericValue.class, jsonData);
            this.phiValue = (ScaledNumericValue) json.readValue("phiValue", ScaledNumericValue.class, jsonData);
        }
    }

    /* loaded from: classes.dex */
    public static class Rotational2D extends Strength {
        ParallelArray.FloatChannel rotationalVelocity2dChannel;

        public Rotational2D() {
        }

        public Rotational2D(Rotational2D rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.rotationalVelocity2dChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.AngularVelocity2D);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int l = 2;
            int s = 0;
            int c = (this.controller.particles.size * this.rotationalVelocity2dChannel.strideSize) + 0;
            while (i < c) {
                float[] fArr = this.rotationalVelocity2dChannel.data;
                fArr[i] = fArr[i] + this.strengthChannel.data[s + 0] + (this.strengthChannel.data[s + 1] * this.strengthValue.getScale(this.lifeChannel.data[l]));
                s += this.strengthChannel.strideSize;
                i += this.rotationalVelocity2dChannel.strideSize;
                l += this.lifeChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Rotational2D copy() {
            return new Rotational2D(this);
        }
    }

    /* loaded from: classes.dex */
    public static class Rotational3D extends Angular {
        ParallelArray.FloatChannel rotationChannel;
        ParallelArray.FloatChannel rotationalForceChannel;

        public Rotational3D() {
        }

        public Rotational3D(Rotational3D rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Angular, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.rotationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Rotation3D);
            this.rotationalForceChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.AngularVelocity3D);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int l = 2;
            int s = 0;
            int a = 0;
            int c = this.controller.particles.size * this.rotationalForceChannel.strideSize;
            while (i < c) {
                float lifePercent = this.lifeChannel.data[l];
                float strength = this.strengthChannel.data[s + 0] + (this.strengthChannel.data[s + 1] * this.strengthValue.getScale(lifePercent));
                float phi = this.angularChannel.data[a + 2] + (this.angularChannel.data[a + 3] * this.phiValue.getScale(lifePercent));
                float theta = this.angularChannel.data[a + 0] + (this.angularChannel.data[a + 1] * this.thetaValue.getScale(lifePercent));
                float cosTheta = MathUtils.cosDeg(theta);
                float sinTheta = MathUtils.sinDeg(theta);
                float cosPhi = MathUtils.cosDeg(phi);
                float sinPhi = MathUtils.sinDeg(phi);
                int c2 = c;
                TMP_V3.set(cosTheta * sinPhi, cosPhi, sinTheta * sinPhi);
                TMP_V3.scl(0.017453292f * strength);
                float[] fArr = this.rotationalForceChannel.data;
                int i2 = i + 0;
                fArr[i2] = fArr[i2] + TMP_V3.x;
                float[] fArr2 = this.rotationalForceChannel.data;
                int i3 = i + 1;
                fArr2[i3] = fArr2[i3] + TMP_V3.y;
                float[] fArr3 = this.rotationalForceChannel.data;
                int i4 = i + 2;
                fArr3[i4] = fArr3[i4] + TMP_V3.z;
                s += this.strengthChannel.strideSize;
                i += this.rotationalForceChannel.strideSize;
                a += this.angularChannel.strideSize;
                l += this.lifeChannel.strideSize;
                c = c2;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Rotational3D copy() {
            return new Rotational3D(this);
        }
    }

    /* loaded from: classes.dex */
    public static class CentripetalAcceleration extends Strength {
        ParallelArray.FloatChannel accelerationChannel;
        ParallelArray.FloatChannel positionChannel;

        public CentripetalAcceleration() {
        }

        public CentripetalAcceleration(CentripetalAcceleration rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.accelerationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Acceleration);
            this.positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            float cx = 0.0f;
            float cy = 0.0f;
            float cz = 0.0f;
            if (!this.isGlobal) {
                float[] val = this.controller.transform.val;
                cx = val[12];
                cy = val[13];
                cz = val[14];
            }
            int lifeOffset = 2;
            int strengthOffset = 0;
            int positionOffset = 0;
            int forceOffset = 0;
            int i = 0;
            int c = this.controller.particles.size;
            while (i < c) {
                float strength = this.strengthChannel.data[strengthOffset + 0] + (this.strengthChannel.data[strengthOffset + 1] * this.strengthValue.getScale(this.lifeChannel.data[lifeOffset]));
                TMP_V3.set(this.positionChannel.data[positionOffset + 0] - cx, this.positionChannel.data[positionOffset + 1] - cy, this.positionChannel.data[positionOffset + 2] - cz).nor().scl(strength);
                float[] fArr = this.accelerationChannel.data;
                int i2 = forceOffset + 0;
                fArr[i2] = fArr[i2] + TMP_V3.x;
                float[] fArr2 = this.accelerationChannel.data;
                int i3 = forceOffset + 1;
                fArr2[i3] = fArr2[i3] + TMP_V3.y;
                float[] fArr3 = this.accelerationChannel.data;
                int i4 = forceOffset + 2;
                fArr3[i4] = fArr3[i4] + TMP_V3.z;
                i++;
                positionOffset += this.positionChannel.strideSize;
                strengthOffset += this.strengthChannel.strideSize;
                forceOffset += this.accelerationChannel.strideSize;
                lifeOffset += this.lifeChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public CentripetalAcceleration copy() {
            return new CentripetalAcceleration(this);
        }
    }

    /* loaded from: classes.dex */
    public static class PolarAcceleration extends Angular {
        ParallelArray.FloatChannel directionalVelocityChannel;

        public PolarAcceleration() {
        }

        public PolarAcceleration(PolarAcceleration rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Angular, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.directionalVelocityChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Acceleration);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int l = 2;
            int s = 0;
            int a = 0;
            int c = (this.controller.particles.size * this.directionalVelocityChannel.strideSize) + 0;
            while (i < c) {
                float lifePercent = this.lifeChannel.data[l];
                float strength = this.strengthChannel.data[s + 0] + (this.strengthChannel.data[s + 1] * this.strengthValue.getScale(lifePercent));
                float phi = this.angularChannel.data[a + 2] + (this.angularChannel.data[a + 3] * this.phiValue.getScale(lifePercent));
                float theta = this.angularChannel.data[a + 0] + (this.angularChannel.data[a + 1] * this.thetaValue.getScale(lifePercent));
                float cosTheta = MathUtils.cosDeg(theta);
                float sinTheta = MathUtils.sinDeg(theta);
                float cosPhi = MathUtils.cosDeg(phi);
                float sinPhi = MathUtils.sinDeg(phi);
                int c2 = c;
                TMP_V3.set(cosTheta * sinPhi, cosPhi, sinTheta * sinPhi).nor().scl(strength);
                if (!this.isGlobal) {
                    this.controller.transform.getRotation(TMP_Q, true);
                    TMP_V3.mul(TMP_Q);
                }
                float[] fArr = this.directionalVelocityChannel.data;
                int i2 = i + 0;
                fArr[i2] = fArr[i2] + TMP_V3.x;
                float[] fArr2 = this.directionalVelocityChannel.data;
                int i3 = i + 1;
                fArr2[i3] = fArr2[i3] + TMP_V3.y;
                float[] fArr3 = this.directionalVelocityChannel.data;
                int i4 = i + 2;
                fArr3[i4] = fArr3[i4] + TMP_V3.z;
                s += this.strengthChannel.strideSize;
                i += this.directionalVelocityChannel.strideSize;
                a += this.angularChannel.strideSize;
                l += this.lifeChannel.strideSize;
                c = c2;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public PolarAcceleration copy() {
            return new PolarAcceleration(this);
        }
    }

    /* loaded from: classes.dex */
    public static class TangentialAcceleration extends Angular {
        ParallelArray.FloatChannel directionalVelocityChannel;
        ParallelArray.FloatChannel positionChannel;

        public TangentialAcceleration() {
        }

        public TangentialAcceleration(TangentialAcceleration rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Angular, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.directionalVelocityChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Acceleration);
            this.positionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Position);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int l = 2;
            int s = 0;
            int a = 0;
            int positionOffset = 0;
            int c = (this.controller.particles.size * this.directionalVelocityChannel.strideSize) + 0;
            while (i < c) {
                float lifePercent = this.lifeChannel.data[l];
                float strength = this.strengthChannel.data[s + 0] + (this.strengthChannel.data[s + 1] * this.strengthValue.getScale(lifePercent));
                float phi = this.angularChannel.data[a + 2] + (this.angularChannel.data[a + 3] * this.phiValue.getScale(lifePercent));
                float theta = this.angularChannel.data[a + 0] + (this.angularChannel.data[a + 1] * this.thetaValue.getScale(lifePercent));
                float cosTheta = MathUtils.cosDeg(theta);
                float sinTheta = MathUtils.sinDeg(theta);
                float cosPhi = MathUtils.cosDeg(phi);
                float sinPhi = MathUtils.sinDeg(phi);
                int c2 = c;
                TMP_V3.set(cosTheta * sinPhi, cosPhi, sinTheta * sinPhi);
                TMP_V1.set(this.positionChannel.data[positionOffset + 0], this.positionChannel.data[positionOffset + 1], this.positionChannel.data[positionOffset + 2]);
                if (!this.isGlobal) {
                    this.controller.transform.getTranslation(TMP_V2);
                    TMP_V1.sub(TMP_V2);
                    this.controller.transform.getRotation(TMP_Q, true);
                    TMP_V3.mul(TMP_Q);
                }
                TMP_V3.crs(TMP_V1).nor().scl(strength);
                float[] fArr = this.directionalVelocityChannel.data;
                int i2 = i + 0;
                fArr[i2] = fArr[i2] + TMP_V3.x;
                float[] fArr2 = this.directionalVelocityChannel.data;
                int i3 = i + 1;
                fArr2[i3] = fArr2[i3] + TMP_V3.y;
                float[] fArr3 = this.directionalVelocityChannel.data;
                int i4 = i + 2;
                fArr3[i4] = fArr3[i4] + TMP_V3.z;
                s += this.strengthChannel.strideSize;
                i += this.directionalVelocityChannel.strideSize;
                a += this.angularChannel.strideSize;
                l += this.lifeChannel.strideSize;
                positionOffset += this.positionChannel.strideSize;
                c = c2;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public TangentialAcceleration copy() {
            return new TangentialAcceleration(this);
        }
    }

    /* loaded from: classes.dex */
    public static class BrownianAcceleration extends Strength {
        ParallelArray.FloatChannel accelerationChannel;

        public BrownianAcceleration() {
        }

        public BrownianAcceleration(BrownianAcceleration rotation) {
            super(rotation);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier.Strength, com.badlogic.gdx.graphics.g3d.particles.influencers.DynamicsModifier, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.accelerationChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Acceleration);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int lifeOffset = 2;
            int strengthOffset = 0;
            int forceOffset = 0;
            int i = 0;
            int c = this.controller.particles.size;
            while (i < c) {
                float strength = this.strengthChannel.data[strengthOffset + 0] + (this.strengthChannel.data[strengthOffset + 1] * this.strengthValue.getScale(this.lifeChannel.data[lifeOffset]));
                TMP_V3.set(MathUtils.random(-1.0f, 1.0f), MathUtils.random(-1.0f, 1.0f), MathUtils.random(-1.0f, 1.0f)).nor().scl(strength);
                float[] fArr = this.accelerationChannel.data;
                int i2 = forceOffset + 0;
                fArr[i2] = fArr[i2] + TMP_V3.x;
                float[] fArr2 = this.accelerationChannel.data;
                int i3 = forceOffset + 1;
                fArr2[i3] = fArr2[i3] + TMP_V3.y;
                float[] fArr3 = this.accelerationChannel.data;
                int i4 = forceOffset + 2;
                fArr3[i4] = fArr3[i4] + TMP_V3.z;
                i++;
                strengthOffset += this.strengthChannel.strideSize;
                forceOffset += this.accelerationChannel.strideSize;
                lifeOffset += this.lifeChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public BrownianAcceleration copy() {
            return new BrownianAcceleration(this);
        }
    }

    public DynamicsModifier() {
        this.isGlobal = false;
    }

    public DynamicsModifier(DynamicsModifier modifier) {
        this.isGlobal = false;
        this.isGlobal = modifier.isGlobal;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.lifeChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Life);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        super.write(json);
        json.writeValue("isGlobal", Boolean.valueOf(this.isGlobal));
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        super.read(json, jsonData);
        this.isGlobal = ((Boolean) json.readValue("isGlobal", Boolean.TYPE, jsonData)).booleanValue();
    }
}