package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Json;
import com.badlogic.gdx.utils.JsonValue;

/* loaded from: classes.dex */
public abstract class RegionInfluencer extends Influencer {
    private static final String ASSET_DATA = "atlasAssetData";
    public String atlasName;
    ParallelArray.FloatChannel regionChannel;
    public Array<AspectTextureRegion> regions;

    /* loaded from: classes.dex */
    public static class Single extends RegionInfluencer {
        public Single() {
        }

        public Single(Single regionInfluencer) {
            super(regionInfluencer);
        }

        public Single(TextureRegion textureRegion) {
            super(textureRegion);
        }

        public Single(Texture texture) {
            super(texture);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void init() {
            AspectTextureRegion region = this.regions.items[0];
            int i = 0;
            int c = this.controller.emitter.maxParticleCount * this.regionChannel.strideSize;
            while (i < c) {
                this.regionChannel.data[i + 0] = region.u;
                this.regionChannel.data[i + 1] = region.v;
                this.regionChannel.data[i + 2] = region.u2;
                this.regionChannel.data[i + 3] = region.v2;
                this.regionChannel.data[i + 4] = 0.5f;
                this.regionChannel.data[i + 5] = region.halfInvAspectRatio;
                i += this.regionChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Single copy() {
            return new Single(this);
        }
    }

    /* loaded from: classes.dex */
    public static class Random extends RegionInfluencer {
        public Random() {
        }

        public Random(Random regionInfluencer) {
            super(regionInfluencer);
        }

        public Random(TextureRegion textureRegion) {
            super(textureRegion);
        }

        public Random(Texture texture) {
            super(texture);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            int i = this.regionChannel.strideSize * startIndex;
            int c = (this.regionChannel.strideSize * count) + i;
            while (i < c) {
                AspectTextureRegion region = this.regions.random();
                this.regionChannel.data[i + 0] = region.u;
                this.regionChannel.data[i + 1] = region.v;
                this.regionChannel.data[i + 2] = region.u2;
                this.regionChannel.data[i + 3] = region.v2;
                this.regionChannel.data[i + 4] = 0.5f;
                this.regionChannel.data[i + 5] = region.halfInvAspectRatio;
                i += this.regionChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Random copy() {
            return new Random(this);
        }
    }

    /* loaded from: classes.dex */
    public static class Animated extends RegionInfluencer {
        ParallelArray.FloatChannel lifeChannel;

        public Animated() {
        }

        public Animated(Animated regionInfluencer) {
            super(regionInfluencer);
        }

        public Animated(TextureRegion textureRegion) {
            super(textureRegion);
        }

        public Animated(Texture texture) {
            super(texture);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.RegionInfluencer, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void allocateChannels() {
            super.allocateChannels();
            this.lifeChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.Life);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void update() {
            int i = 0;
            int l = 2;
            int c = this.controller.particles.size * this.regionChannel.strideSize;
            while (i < c) {
                AspectTextureRegion region = this.regions.get((int) (this.lifeChannel.data[l] * (this.regions.size - 1)));
                this.regionChannel.data[i + 0] = region.u;
                this.regionChannel.data[i + 1] = region.v;
                this.regionChannel.data[i + 2] = region.u2;
                this.regionChannel.data[i + 3] = region.v2;
                this.regionChannel.data[i + 4] = 0.5f;
                this.regionChannel.data[i + 5] = region.halfInvAspectRatio;
                i += this.regionChannel.strideSize;
                l += this.lifeChannel.strideSize;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Animated copy() {
            return new Animated(this);
        }
    }

    /* loaded from: classes.dex */
    public static class AspectTextureRegion {
        public float halfInvAspectRatio;
        public String imageName;
        public float u;
        public float u2;
        public float v;
        public float v2;

        public AspectTextureRegion() {
        }

        public AspectTextureRegion(AspectTextureRegion aspectTextureRegion) {
            set(aspectTextureRegion);
        }

        public AspectTextureRegion(TextureRegion region) {
            set(region);
        }

        public void set(TextureRegion region) {
            this.u = region.getU();
            this.v = region.getV();
            this.u2 = region.getU2();
            this.v2 = region.getV2();
            this.halfInvAspectRatio = (region.getRegionHeight() / region.getRegionWidth()) * 0.5f;
            if (region instanceof TextureAtlas.AtlasRegion) {
                this.imageName = ((TextureAtlas.AtlasRegion) region).name;
            }
        }

        public void set(AspectTextureRegion aspectTextureRegion) {
            this.u = aspectTextureRegion.u;
            this.v = aspectTextureRegion.v;
            this.u2 = aspectTextureRegion.u2;
            this.v2 = aspectTextureRegion.v2;
            this.halfInvAspectRatio = aspectTextureRegion.halfInvAspectRatio;
            this.imageName = aspectTextureRegion.imageName;
        }

        public void updateUV(TextureAtlas atlas) {
            String str = this.imageName;
            if (str == null) {
                return;
            }
            TextureAtlas.AtlasRegion region = atlas.findRegion(str);
            this.u = region.getU();
            this.v = region.getV();
            this.u2 = region.getU2();
            this.v2 = region.getV2();
            this.halfInvAspectRatio = (region.getRegionHeight() / region.getRegionWidth()) * 0.5f;
        }
    }

    public RegionInfluencer(int regionsCount) {
        this.regions = new Array<>(false, regionsCount, AspectTextureRegion.class);
    }

    public RegionInfluencer() {
        this(1);
        AspectTextureRegion aspectRegion = new AspectTextureRegion();
        aspectRegion.v = 0.0f;
        aspectRegion.u = 0.0f;
        aspectRegion.v2 = 1.0f;
        aspectRegion.u2 = 1.0f;
        aspectRegion.halfInvAspectRatio = 0.5f;
        this.regions.add(aspectRegion);
    }

    public RegionInfluencer(TextureRegion... regions) {
        setAtlasName(null);
        this.regions = new Array<>(false, regions.length, AspectTextureRegion.class);
        add(regions);
    }

    public RegionInfluencer(Texture texture) {
        this(new TextureRegion(texture));
    }

    public RegionInfluencer(RegionInfluencer regionInfluencer) {
        this(regionInfluencer.regions.size);
        this.regions.ensureCapacity(regionInfluencer.regions.size);
        for (int i = 0; i < regionInfluencer.regions.size; i++) {
            this.regions.add(new AspectTextureRegion(regionInfluencer.regions.get(i)));
        }
    }

    public void setAtlasName(String atlasName) {
        this.atlasName = atlasName;
    }

    public void add(TextureRegion... regions) {
        this.regions.ensureCapacity(regions.length);
        for (TextureRegion region : regions) {
            this.regions.add(new AspectTextureRegion(region));
        }
    }

    public void clear() {
        this.atlasName = null;
        this.regions.clear();
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData resources) {
        super.load(manager, resources);
        ResourceData.SaveData data = resources.getSaveData(ASSET_DATA);
        if (data == null) {
            return;
        }
        TextureAtlas atlas = (TextureAtlas) manager.get(data.loadAsset());
        Array.ArrayIterator<AspectTextureRegion> it = this.regions.iterator();
        while (it.hasNext()) {
            AspectTextureRegion atr = it.next();
            atr.updateUV(atlas);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData resources) {
        super.save(manager, resources);
        if (this.atlasName != null) {
            ResourceData.SaveData data = resources.getSaveData(ASSET_DATA);
            if (data == null) {
                data = resources.createSaveData(ASSET_DATA);
            }
            data.saveAsset(this.atlasName, TextureAtlas.class);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.regionChannel = (ParallelArray.FloatChannel) this.controller.particles.addChannel(ParticleChannels.TextureRegion);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void write(Json json) {
        json.writeValue("regions", this.regions, Array.class, AspectTextureRegion.class);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Json.Serializable
    public void read(Json json, JsonValue jsonData) {
        this.regions.clear();
        this.regions.addAll((Array) json.readValue("regions", (Class<Object>) Array.class, AspectTextureRegion.class, jsonData));
    }
}