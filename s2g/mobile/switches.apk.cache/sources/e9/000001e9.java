package com.badlogic.gdx.graphics.g3d.particles.influencers;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.g3d.particles.ParallelArray;
import com.badlogic.gdx.graphics.g3d.particles.ParticleChannels;
import com.badlogic.gdx.graphics.g3d.particles.ParticleController;
import com.badlogic.gdx.graphics.g3d.particles.ParticleEffect;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.Pool;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class ParticleControllerInfluencer extends Influencer {
    ParallelArray.ObjectChannel<ParticleController> particleControllerChannel;
    public Array<ParticleController> templates;

    /* loaded from: classes.dex */
    public static class Single extends ParticleControllerInfluencer {
        public Single(ParticleController... templates) {
            super(templates);
        }

        public Single() {
        }

        public Single(Single particleControllerSingle) {
            super(particleControllerSingle);
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void init() {
            ParticleController first = this.templates.first();
            int c = this.controller.particles.capacity;
            for (int i = 0; i < c; i++) {
                ParticleController copy = first.copy();
                copy.init();
                this.particleControllerChannel.data[i] = copy;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                this.particleControllerChannel.data[i].start();
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void killParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                this.particleControllerChannel.data[i].end();
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Single copy() {
            return new Single(this);
        }
    }

    /* loaded from: classes.dex */
    public static class Random extends ParticleControllerInfluencer {
        ParticleControllerPool pool;

        /* loaded from: classes.dex */
        private class ParticleControllerPool extends Pool<ParticleController> {
            public ParticleControllerPool() {
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.badlogic.gdx.utils.Pool
            public ParticleController newObject() {
                ParticleController controller = Random.this.templates.random().copy();
                controller.init();
                return controller;
            }

            @Override // com.badlogic.gdx.utils.Pool
            public void clear() {
                int free = Random.this.pool.getFree();
                for (int i = 0; i < free; i++) {
                    Random.this.pool.obtain().dispose();
                }
                super.clear();
            }
        }

        public Random() {
            this.pool = new ParticleControllerPool();
        }

        public Random(ParticleController... templates) {
            super(templates);
            this.pool = new ParticleControllerPool();
        }

        public Random(Random particleControllerRandom) {
            super(particleControllerRandom);
            this.pool = new ParticleControllerPool();
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void init() {
            this.pool.clear();
            for (int i = 0; i < this.controller.emitter.maxParticleCount; i++) {
                ParticleControllerPool particleControllerPool = this.pool;
                particleControllerPool.free(particleControllerPool.newObject());
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.influencers.ParticleControllerInfluencer, com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Disposable
        public void dispose() {
            this.pool.clear();
            super.dispose();
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void activateParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                ParticleController controller = this.pool.obtain();
                controller.start();
                this.particleControllerChannel.data[i] = controller;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public void killParticles(int startIndex, int count) {
            int c = startIndex + count;
            for (int i = startIndex; i < c; i++) {
                ParticleController controller = this.particleControllerChannel.data[i];
                controller.end();
                this.pool.free(controller);
                this.particleControllerChannel.data[i] = null;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
        public Random copy() {
            return new Random(this);
        }
    }

    public ParticleControllerInfluencer() {
        this.templates = new Array<>(true, 1, ParticleController.class);
    }

    public ParticleControllerInfluencer(ParticleController... templates) {
        this.templates = new Array<>(templates);
    }

    public ParticleControllerInfluencer(ParticleControllerInfluencer influencer) {
        this(influencer.templates.items);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void allocateChannels() {
        this.particleControllerChannel = (ParallelArray.ObjectChannel) this.controller.particles.addChannel(ParticleChannels.ParticleController);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent
    public void end() {
        for (int i = 0; i < this.controller.particles.size; i++) {
            this.particleControllerChannel.data[i].end();
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.controller != null) {
            for (int i = 0; i < this.controller.particles.size; i++) {
                ParticleController controller = this.particleControllerChannel.data[i];
                if (controller != null) {
                    controller.dispose();
                    this.particleControllerChannel.data[i] = null;
                }
            }
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.createSaveData();
        Array<ParticleEffect> effects = manager.getAll(ParticleEffect.class, new Array());
        Array<ParticleController> controllers = new Array<>(this.templates);
        Array<IntArray> effectsIndices = new Array<>();
        for (int i = 0; i < effects.size && controllers.size > 0; i++) {
            ParticleEffect effect = effects.get(i);
            Array<ParticleController> effectControllers = effect.getControllers();
            Iterator<ParticleController> iterator = controllers.iterator();
            IntArray indices = null;
            while (iterator.hasNext()) {
                ParticleController controller = iterator.next();
                int index = effectControllers.indexOf(controller, true);
                if (index > -1) {
                    if (indices == null) {
                        indices = new IntArray();
                    }
                    iterator.remove();
                    indices.add(index);
                }
            }
            if (indices != null) {
                data.saveAsset(manager.getAssetFileName(effect), ParticleEffect.class);
                effectsIndices.add(indices);
            }
        }
        data.save("indices", effectsIndices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleControllerComponent, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData resources) {
        ResourceData.SaveData data = resources.getSaveData();
        Array<IntArray> effectsIndices = (Array) data.load("indices");
        Iterator<IntArray> iterator = effectsIndices.iterator();
        while (true) {
            AssetDescriptor descriptor = data.loadAsset();
            if (descriptor != null) {
                ParticleEffect effect = (ParticleEffect) manager.get(descriptor);
                if (effect == null) {
                    throw new RuntimeException("Template is null");
                }
                Array<ParticleController> effectControllers = effect.getControllers();
                IntArray effectIndices = iterator.next();
                int n = effectIndices.size;
                for (int i = 0; i < n; i++) {
                    this.templates.add(effectControllers.get(effectIndices.get(i)));
                }
            } else {
                return;
            }
        }
    }
}