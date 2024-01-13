package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.g3d.Model;
import com.badlogic.gdx.graphics.g3d.ModelInstance;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public abstract class ModelInfluencer extends Influencer {
    ParallelArray.ObjectChannel<ModelInstance> modelChannel;
    public Array<Model> models;

    /* loaded from: classes.dex */
    public static class Single extends ModelInfluencer {
        public Single() {
        }

        public Single(Single influencer) {
            super(influencer);
        }

        public Single(Model... models) {
            super(models);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void init() {
            Model first = this.models.first();
            int c = this.controller.emitter.maxParticleCount;
            for (int i = 0; i < c; i++) {
                this.modelChannel.data[i] = new ModelInstance(first);
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Single copy() {
            return new Single(this);
        }
    }

    /* loaded from: classes.dex */
    public static class Random extends ModelInfluencer {
        ModelInstancePool pool;

        /* loaded from: classes.dex */
        private class ModelInstancePool extends Pool<ModelInstance> {
            public ModelInstancePool() {
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.badlogic.gdx.utils.Pool
            public ModelInstance newObject() {
                return new ModelInstance(Random.this.models.random());
            }
        }

        public Random() {
            this.pool = new ModelInstancePool();
        }

        public Random(Random influencer) {
            super(influencer);
            this.pool = new ModelInstancePool();
        }

        public Random(Model... models) {
            super(models);
            this.pool = new ModelInstancePool();
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void init() {
            this.pool.clear();
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                this.modelChannel.data[i] = this.pool.obtain();
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void killParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                this.pool.free(this.modelChannel.data[i]);
                this.modelChannel.data[i] = null;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Random copy() {
            return new Random(this);
        }
    }

    public ModelInfluencer() {
        this.models = new Array<>(true, 1, Model.class);
    }

    public ModelInfluencer(Model... models) {
        this.models = new Array<>(models);
    }

    public ModelInfluencer(ModelInfluencer influencer) {
        this((Model[]) influencer.models.toArray(Model.class));
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.modelChannel = (ParallelArray.ObjectChannel) this.controller.particles.addChannel(ParticleChannels.ModelInstance);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.createSaveData();
        Array.ArrayIterator<Model> it = this.models.iterator();
        while (it.hasNext()) {
            Model model = it.next();
            data.saveAsset(manager.getAssetFileName(model), Model.class);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.getSaveData();
        while (true) {
            AssetDescriptor descriptor = data.loadAsset();
            if (descriptor != null) {
                Model model = (Model) manager.get(descriptor);
                if (model == null) {
                    throw new RuntimeException("Model is null");
                }
                this.models.add(model);
            } else {
                return;
            }
        }
    }
}