package com.badlogic.gdx.graphics.g3d.particles.batches;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.g3d.particles.ParticleSorter;
import com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderData;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public abstract class BufferedParticleBatch<T extends ParticleControllerRenderData> implements ParticleBatch<T> {
    protected int bufferedParticlesCount;
    protected Camera camera;
    protected Array<T> renderData;
    protected int currentCapacity = 0;
    protected ParticleSorter sorter = new ParticleSorter.Distance();

    protected abstract void allocParticlesData(int i);

    protected abstract void flush(int[] iArr);

    /* JADX INFO: Access modifiers changed from: protected */
    public BufferedParticleBatch(Class<T> type) {
        this.renderData = new Array<>(false, 10, type);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void begin() {
        this.renderData.clear();
        this.bufferedParticlesCount = 0;
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void draw(T data) {
        if (data.controller.particles.size > 0) {
            this.renderData.add(data);
            this.bufferedParticlesCount += data.controller.particles.size;
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.batches.ParticleBatch
    public void end() {
        int i = this.bufferedParticlesCount;
        if (i > 0) {
            ensureCapacity(i);
            flush(this.sorter.sort(this.renderData));
        }
    }

    public void ensureCapacity(int capacity) {
        if (this.currentCapacity >= capacity) {
            return;
        }
        this.sorter.ensureCapacity(capacity);
        allocParticlesData(capacity);
        this.currentCapacity = capacity;
    }

    public void resetCapacity() {
        this.bufferedParticlesCount = 0;
        this.currentCapacity = 0;
    }

    public void setCamera(Camera camera) {
        this.camera = camera;
        this.sorter.setCamera(camera);
    }

    public ParticleSorter getSorter() {
        return this.sorter;
    }

    public void setSorter(ParticleSorter sorter) {
        this.sorter = sorter;
        sorter.setCamera(this.camera);
        sorter.ensureCapacity(this.currentCapacity);
    }

    public int getBufferedCount() {
        return this.bufferedParticlesCount;
    }
}