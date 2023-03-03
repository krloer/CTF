package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.graphics.g3d.ModelInstance;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import java.util.Arrays;

/* loaded from: classes.dex */
public class ParticleChannels {
    public static final int AlphaOffset = 3;
    public static final int BlueOffset = 2;
    public static final int CosineOffset = 0;
    public static final int CurrentLifeOffset = 0;
    public static final int GreenOffset = 1;
    public static final int HalfHeightOffset = 5;
    public static final int HalfWidthOffset = 4;
    public static final int InterpolationDiffOffset = 1;
    public static final int InterpolationStartOffset = 0;
    public static final int LifePercentOffset = 2;
    public static final int RedOffset = 0;
    public static final int SineOffset = 1;
    public static final int TotalLifeOffset = 1;
    public static final int U2Offset = 2;
    public static final int UOffset = 0;
    public static final int V2Offset = 3;
    public static final int VOffset = 1;
    public static final int VelocityPhiDiffOffset = 3;
    public static final int VelocityPhiStartOffset = 2;
    public static final int VelocityStrengthDiffOffset = 1;
    public static final int VelocityStrengthStartOffset = 0;
    public static final int VelocityThetaDiffOffset = 1;
    public static final int VelocityThetaStartOffset = 0;
    public static final int WOffset = 3;
    public static final int XOffset = 0;
    public static final int YOffset = 1;
    public static final int ZOffset = 2;
    private static int currentGlobalId;
    private int currentId;
    public static final ParallelArray.ChannelDescriptor Life = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 3);
    public static final ParallelArray.ChannelDescriptor Position = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 3);
    public static final ParallelArray.ChannelDescriptor PreviousPosition = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 3);
    public static final ParallelArray.ChannelDescriptor Color = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 4);
    public static final ParallelArray.ChannelDescriptor TextureRegion = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 6);
    public static final ParallelArray.ChannelDescriptor Rotation2D = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 2);
    public static final ParallelArray.ChannelDescriptor Rotation3D = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 4);
    public static final ParallelArray.ChannelDescriptor Scale = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 1);
    public static final ParallelArray.ChannelDescriptor ModelInstance = new ParallelArray.ChannelDescriptor(newGlobalId(), ModelInstance.class, 1);
    public static final ParallelArray.ChannelDescriptor ParticleController = new ParallelArray.ChannelDescriptor(newGlobalId(), ParticleController.class, 1);
    public static final ParallelArray.ChannelDescriptor Acceleration = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 3);
    public static final ParallelArray.ChannelDescriptor AngularVelocity2D = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 1);
    public static final ParallelArray.ChannelDescriptor AngularVelocity3D = new ParallelArray.ChannelDescriptor(newGlobalId(), Float.TYPE, 3);
    public static final ParallelArray.ChannelDescriptor Interpolation = new ParallelArray.ChannelDescriptor(-1, Float.TYPE, 2);
    public static final ParallelArray.ChannelDescriptor Interpolation4 = new ParallelArray.ChannelDescriptor(-1, Float.TYPE, 4);
    public static final ParallelArray.ChannelDescriptor Interpolation6 = new ParallelArray.ChannelDescriptor(-1, Float.TYPE, 6);

    public static int newGlobalId() {
        int i = currentGlobalId;
        currentGlobalId = i + 1;
        return i;
    }

    /* loaded from: classes.dex */
    public static class TextureRegionInitializer implements ParallelArray.ChannelInitializer<ParallelArray.FloatChannel> {
        private static TextureRegionInitializer instance;

        public static TextureRegionInitializer get() {
            if (instance == null) {
                instance = new TextureRegionInitializer();
            }
            return instance;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.ChannelInitializer
        public void init(ParallelArray.FloatChannel channel) {
            int i = 0;
            int c = channel.data.length;
            while (i < c) {
                channel.data[i + 0] = 0.0f;
                channel.data[i + 1] = 0.0f;
                channel.data[i + 2] = 1.0f;
                channel.data[i + 3] = 1.0f;
                channel.data[i + 4] = 0.5f;
                channel.data[i + 5] = 0.5f;
                i += channel.strideSize;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class ColorInitializer implements ParallelArray.ChannelInitializer<ParallelArray.FloatChannel> {
        private static ColorInitializer instance;

        public static ColorInitializer get() {
            if (instance == null) {
                instance = new ColorInitializer();
            }
            return instance;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.ChannelInitializer
        public void init(ParallelArray.FloatChannel channel) {
            Arrays.fill(channel.data, 0, channel.data.length, 1.0f);
        }
    }

    /* loaded from: classes.dex */
    public static class ScaleInitializer implements ParallelArray.ChannelInitializer<ParallelArray.FloatChannel> {
        private static ScaleInitializer instance;

        public static ScaleInitializer get() {
            if (instance == null) {
                instance = new ScaleInitializer();
            }
            return instance;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.ChannelInitializer
        public void init(ParallelArray.FloatChannel channel) {
            Arrays.fill(channel.data, 0, channel.data.length, 1.0f);
        }
    }

    /* loaded from: classes.dex */
    public static class Rotation2dInitializer implements ParallelArray.ChannelInitializer<ParallelArray.FloatChannel> {
        private static Rotation2dInitializer instance;

        public static Rotation2dInitializer get() {
            if (instance == null) {
                instance = new Rotation2dInitializer();
            }
            return instance;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.ChannelInitializer
        public void init(ParallelArray.FloatChannel channel) {
            int i = 0;
            int c = channel.data.length;
            while (i < c) {
                channel.data[i + 0] = 1.0f;
                channel.data[i + 1] = 0.0f;
                i += channel.strideSize;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class Rotation3dInitializer implements ParallelArray.ChannelInitializer<ParallelArray.FloatChannel> {
        private static Rotation3dInitializer instance;

        public static Rotation3dInitializer get() {
            if (instance == null) {
                instance = new Rotation3dInitializer();
            }
            return instance;
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParallelArray.ChannelInitializer
        public void init(ParallelArray.FloatChannel channel) {
            int i = 0;
            int c = channel.data.length;
            while (i < c) {
                channel.data[i + 2] = 0.0f;
                channel.data[i + 1] = 0.0f;
                channel.data[i + 0] = 0.0f;
                channel.data[i + 3] = 1.0f;
                i += channel.strideSize;
            }
        }
    }

    public ParticleChannels() {
        resetIds();
    }

    public int newId() {
        int i = this.currentId;
        this.currentId = i + 1;
        return i;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void resetIds() {
        this.currentId = currentGlobalId;
    }
}