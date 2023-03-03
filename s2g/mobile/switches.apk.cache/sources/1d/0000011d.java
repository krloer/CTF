package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class ParticleEffectPool extends Pool<PooledEffect> {
    private final ParticleEffect effect;

    public ParticleEffectPool(ParticleEffect effect, int initialCapacity, int max) {
        super(initialCapacity, max);
        this.effect = effect;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.badlogic.gdx.utils.Pool
    public PooledEffect newObject() {
        PooledEffect pooledEffect = new PooledEffect(this.effect);
        pooledEffect.start();
        return pooledEffect;
    }

    @Override // com.badlogic.gdx.utils.Pool
    public void free(PooledEffect effect) {
        super.free((ParticleEffectPool) effect);
        effect.reset(false);
        if (effect.xSizeScale != this.effect.xSizeScale || effect.ySizeScale != this.effect.ySizeScale || effect.motionScale != this.effect.motionScale) {
            Array<ParticleEmitter> emitters = effect.getEmitters();
            Array<ParticleEmitter> templateEmitters = this.effect.getEmitters();
            for (int i = 0; i < emitters.size; i++) {
                ParticleEmitter emitter = emitters.get(i);
                ParticleEmitter templateEmitter = templateEmitters.get(i);
                emitter.matchSize(templateEmitter);
                emitter.matchMotion(templateEmitter);
            }
            effect.xSizeScale = this.effect.xSizeScale;
            effect.ySizeScale = this.effect.ySizeScale;
            effect.motionScale = this.effect.motionScale;
        }
    }

    /* loaded from: classes.dex */
    public class PooledEffect extends ParticleEffect {
        PooledEffect(ParticleEffect effect) {
            super(effect);
        }

        public void free() {
            ParticleEffectPool.this.free(this);
        }
    }
}