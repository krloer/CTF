package com.badlogic.gdx.graphics.g3d.particles;

import com.badlogic.gdx.graphics.Camera;
import com.badlogic.gdx.graphics.g3d.particles.renderers.ParticleControllerRenderData;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public abstract class ParticleSorter {
    static final Vector3 TMP_V1 = new Vector3();
    protected Camera camera;

    public abstract <T extends ParticleControllerRenderData> int[] sort(Array<T> array);

    /* loaded from: classes.dex */
    public static class None extends ParticleSorter {
        int currentCapacity = 0;
        int[] indices;

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleSorter
        public void ensureCapacity(int capacity) {
            if (this.currentCapacity < capacity) {
                this.indices = new int[capacity];
                for (int i = 0; i < capacity; i++) {
                    this.indices[i] = i;
                }
                this.currentCapacity = capacity;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleSorter
        public <T extends ParticleControllerRenderData> int[] sort(Array<T> renderData) {
            return this.indices;
        }
    }

    /* loaded from: classes.dex */
    public static class Distance extends ParticleSorter {
        private int currentSize = 0;
        private float[] distances;
        private int[] particleIndices;
        private int[] particleOffsets;

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleSorter
        public void ensureCapacity(int capacity) {
            if (this.currentSize < capacity) {
                this.distances = new float[capacity];
                this.particleIndices = new int[capacity];
                this.particleOffsets = new int[capacity];
                this.currentSize = capacity;
            }
        }

        @Override // com.badlogic.gdx.graphics.g3d.particles.ParticleSorter
        public <T extends ParticleControllerRenderData> int[] sort(Array<T> renderData) {
            float[] val = this.camera.view.val;
            float cx = val[2];
            float cy = val[6];
            float cz = val[10];
            int count = 0;
            int i = 0;
            Array.ArrayIterator<T> it = renderData.iterator();
            while (it.hasNext()) {
                ParticleControllerRenderData data = it.next();
                int k = 0;
                int c = data.controller.particles.size + i;
                while (i < c) {
                    this.distances[i] = (data.positionChannel.data[k + 0] * cx) + (data.positionChannel.data[k + 1] * cy) + (data.positionChannel.data[k + 2] * cz);
                    this.particleIndices[i] = i;
                    i++;
                    k += data.positionChannel.strideSize;
                }
                count += data.controller.particles.size;
            }
            qsort(0, count - 1);
            for (int i2 = 0; i2 < count; i2++) {
                this.particleOffsets[this.particleIndices[i2]] = i2;
            }
            return this.particleOffsets;
        }

        public void qsort(int si, int ei) {
            if (si < ei) {
                if (ei - si <= 8) {
                    for (int i = si; i <= ei; i++) {
                        for (int j = i; j > si; j--) {
                            float[] fArr = this.distances;
                            if (fArr[j - 1] > fArr[j]) {
                                float tmp = fArr[j];
                                fArr[j] = fArr[j - 1];
                                fArr[j - 1] = tmp;
                                int[] iArr = this.particleIndices;
                                int tmpIndex = iArr[j];
                                iArr[j] = iArr[j - 1];
                                iArr[j - 1] = tmpIndex;
                            }
                        }
                    }
                    return;
                }
                float pivot = this.distances[si];
                int i2 = si + 1;
                int particlesPivotIndex = this.particleIndices[si];
                for (int j2 = si + 1; j2 <= ei; j2++) {
                    float[] fArr2 = this.distances;
                    if (pivot > fArr2[j2]) {
                        if (j2 > i2) {
                            float tmp2 = fArr2[j2];
                            fArr2[j2] = fArr2[i2];
                            fArr2[i2] = tmp2;
                            int[] iArr2 = this.particleIndices;
                            int tmpIndex2 = iArr2[j2];
                            iArr2[j2] = iArr2[i2];
                            iArr2[i2] = tmpIndex2;
                        }
                        i2++;
                    }
                }
                float[] fArr3 = this.distances;
                fArr3[si] = fArr3[i2 - 1];
                fArr3[i2 - 1] = pivot;
                int[] iArr3 = this.particleIndices;
                iArr3[si] = iArr3[i2 - 1];
                iArr3[i2 - 1] = particlesPivotIndex;
                qsort(si, i2 - 2);
                qsort(i2, ei);
            }
        }
    }

    public void setCamera(Camera camera) {
        this.camera = camera;
    }

    public void ensureCapacity(int capacity) {
    }
}