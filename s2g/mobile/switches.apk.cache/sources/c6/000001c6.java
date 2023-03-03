package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.RenderableProvider;
import com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public final class ParticleSystem implements RenderableProvider {
    private static ParticleSystem instance;
    private Array<ParticleBatch<?>> batches = new Array<>();
    private Array<ParticleEffect> effects = new Array<>();

    @Deprecated
    public static ParticleSystem get() {
        if (instance == null) {
            instance = new ParticleSystem();
        }
        return instance;
    }

    public void add(ParticleBatch<?> batch) {
        this.batches.add(batch);
    }

    public void add(ParticleEffect effect) {
        this.effects.add(effect);
    }

    public void remove(ParticleEffect effect) {
        this.effects.removeValue(effect, true);
    }

    public void removeAll() {
        this.effects.clear();
    }

    public void update() {
        Array.ArrayIterator<ParticleEffect> it = this.effects.iterator();
        while (it.hasNext()) {
            ParticleEffect effect = it.next();
            effect.update();
        }
    }

    public void updateAndDraw() {
        Array.ArrayIterator<ParticleEffect> it = this.effects.iterator();
        while (it.hasNext()) {
            ParticleEffect effect = it.next();
            effect.update();
            effect.draw();
        }
    }

    public void update(float deltaTime) {
        Array.ArrayIterator<ParticleEffect> it = this.effects.iterator();
        while (it.hasNext()) {
            ParticleEffect effect = it.next();
            effect.update(deltaTime);
        }
    }

    public void updateAndDraw(float deltaTime) {
        Array.ArrayIterator<ParticleEffect> it = this.effects.iterator();
        while (it.hasNext()) {
            ParticleEffect effect = it.next();
            effect.update(deltaTime);
            effect.draw();
        }
    }

    public void begin() {
        Array.ArrayIterator<ParticleBatch<?>> it = this.batches.iterator();
        while (it.hasNext()) {
            ParticleBatch<?> batch = it.next();
            batch.begin();
        }
    }

    public void draw() {
        Array.ArrayIterator<ParticleEffect> it = this.effects.iterator();
        while (it.hasNext()) {
            ParticleEffect effect = it.next();
            effect.draw();
        }
    }

    public void end() {
        Array.ArrayIterator<ParticleBatch<?>> it = this.batches.iterator();
        while (it.hasNext()) {
            ParticleBatch<?> batch = it.next();
            batch.end();
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.RenderableProvider
    public void getRenderables(Array<Renderable> renderables, Pool<Renderable> pool) {
        Array.ArrayIterator<ParticleBatch<?>> it = this.batches.iterator();
        while (it.hasNext()) {
            ParticleBatch<?> batch = it.next();
            batch.getRenderables(renderables, pool);
        }
    }

    public Array<ParticleBatch<?>> getBatches() {
        return this.batches;
    }
}