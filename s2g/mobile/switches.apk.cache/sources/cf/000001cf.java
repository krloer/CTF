package com.badlogic.gdx.graphics.g3d.particles.batches;

import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.graphics.g3d.particles.renderers.ModelInstanceControllerRenderData;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class ModelInstanceParticleBatch implements ParticleBatch<ModelInstanceControllerRenderData> {
    int bufferedParticlesCount;
    Array<ModelInstanceControllerRenderData> controllersRenderData = new Array<>(false, 5);

    @Override // com.badlogic.gdx.graphics.g3d.RenderableProvider
    public void getRenderables(Array<Renderable> renderables, Pool<Renderable> pool) {
        Array.ArrayIterator<ModelInstanceControllerRenderData> it = this.controllersRenderData.iterator();
        while (it.hasNext()) {
            ModelInstanceControllerRenderData data = it.next();
            int count = data.controller.particles.size;
            for (int i = 0; i < count; i++) {
                data.modelInstanceChannel.data[i].getRenderables(renderables, pool);
            }
        }
    }

    public int getBufferedCount() {
        return this.bufferedParticlesCount;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void begin() {
        this.controllersRenderData.clear();
        this.bufferedParticlesCount = 0;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void end() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void draw(ModelInstanceControllerRenderData data) {
        this.controllersRenderData.add(data);
        this.bufferedParticlesCount += data.controller.particles.size;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData assetDependencyData) {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData assetDependencyData) {
    }
}