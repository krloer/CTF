package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.g3d.ModelInstance;
import com.badlogic.gdx.graphics.g3d.model.Animation;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.Pool;

/* loaded from: classes.dex */
public class AnimationController extends BaseAnimationController {
    public boolean allowSameAnimation;
    protected final Pool<AnimationDesc> animationPool;
    public AnimationDesc current;
    public boolean inAction;
    private boolean justChangedAnimation;
    public boolean paused;
    public AnimationDesc previous;
    public AnimationDesc queued;
    public float queuedTransitionTime;
    public float transitionCurrentTime;
    public float transitionTargetTime;

    /* loaded from: classes.dex */
    public interface AnimationListener {
        void onEnd(AnimationDesc animationDesc);

        void onLoop(AnimationDesc animationDesc);
    }

    /* loaded from: classes.dex */
    public static class AnimationDesc {
        public Animation animation;
        public float duration;
        public AnimationListener listener;
        public int loopCount;
        public float offset;
        public float speed;
        public float time;

        protected AnimationDesc() {
        }

        protected float update(float delta) {
            int loops;
            AnimationListener animationListener;
            if (this.loopCount != 0 && this.animation != null) {
                float diff = this.speed * delta;
                if (!MathUtils.isZero(this.duration)) {
                    this.time += diff;
                    if (this.speed < 0.0f) {
                        float f = this.duration;
                        float invTime = f - this.time;
                        loops = (int) Math.abs(invTime / f);
                        this.time = this.duration - Math.abs(invTime % this.duration);
                    } else {
                        loops = (int) Math.abs(this.time / this.duration);
                        this.time = Math.abs(this.time % this.duration);
                    }
                } else {
                    loops = 1;
                }
                for (int i = 0; i < loops; i++) {
                    int i2 = this.loopCount;
                    if (i2 > 0) {
                        this.loopCount = i2 - 1;
                    }
                    if (this.loopCount != 0 && (animationListener = this.listener) != null) {
                        animationListener.onLoop(this);
                    }
                    if (this.loopCount == 0) {
                        float f2 = this.duration;
                        float result = (((loops - 1) - i) * f2) + (diff < 0.0f ? f2 - this.time : this.time);
                        this.time = diff >= 0.0f ? this.duration : 0.0f;
                        AnimationListener animationListener2 = this.listener;
                        if (animationListener2 != null) {
                            animationListener2.onEnd(this);
                        }
                        return result;
                    }
                }
                return -1.0f;
            }
            return delta;
        }
    }

    public AnimationController(ModelInstance target) {
        super(target);
        this.animationPool = new Pool<AnimationDesc>() { // from class: com.badlogic.gdx.graphics.g3d.utils.AnimationController.1
            /* JADX INFO: Access modifiers changed from: protected */
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.badlogic.gdx.utils.Pool
            public AnimationDesc newObject() {
                return new AnimationDesc();
            }
        };
        this.justChangedAnimation = false;
    }

    private AnimationDesc obtain(Animation anim, float offset, float duration, int loopCount, float speed, AnimationListener listener) {
        if (anim == null) {
            return null;
        }
        AnimationDesc result = this.animationPool.obtain();
        result.animation = anim;
        result.listener = listener;
        result.loopCount = loopCount;
        result.speed = speed;
        result.offset = offset;
        result.duration = duration < 0.0f ? anim.duration - offset : duration;
        result.time = speed < 0.0f ? result.duration : 0.0f;
        return result;
    }

    private AnimationDesc obtain(String id, float offset, float duration, int loopCount, float speed, AnimationListener listener) {
        if (id == null) {
            return null;
        }
        Animation anim = this.target.getAnimation(id);
        if (anim == null) {
            throw new GdxRuntimeException("Unknown animation: " + id);
        }
        return obtain(anim, offset, duration, loopCount, speed, listener);
    }

    private AnimationDesc obtain(AnimationDesc anim) {
        return obtain(anim.animation, anim.offset, anim.duration, anim.loopCount, anim.speed, anim.listener);
    }

    public void update(float delta) {
        AnimationDesc animationDesc;
        if (this.paused) {
            return;
        }
        AnimationDesc animationDesc2 = this.previous;
        if (animationDesc2 != null) {
            float f = this.transitionCurrentTime + delta;
            this.transitionCurrentTime = f;
            if (f >= this.transitionTargetTime) {
                removeAnimation(animationDesc2.animation);
                this.justChangedAnimation = true;
                this.animationPool.free(this.previous);
                this.previous = null;
            }
        }
        if (this.justChangedAnimation) {
            this.target.calculateTransforms();
            this.justChangedAnimation = false;
        }
        AnimationDesc animationDesc3 = this.current;
        if (animationDesc3 == null || animationDesc3.loopCount == 0 || this.current.animation == null) {
            return;
        }
        float remain = this.current.update(delta);
        if (remain >= 0.0f && (animationDesc = this.queued) != null) {
            this.inAction = false;
            animate(animationDesc, this.queuedTransitionTime);
            this.queued = null;
            if (remain > 0.0f) {
                update(remain);
                return;
            }
            return;
        }
        AnimationDesc animationDesc4 = this.previous;
        if (animationDesc4 != null) {
            applyAnimations(animationDesc4.animation, this.previous.offset + this.previous.time, this.current.animation, this.current.offset + this.current.time, this.transitionCurrentTime / this.transitionTargetTime);
        } else {
            applyAnimation(this.current.animation, this.current.offset + this.current.time);
        }
    }

    public AnimationDesc setAnimation(String id) {
        return setAnimation(id, 1, 1.0f, null);
    }

    public AnimationDesc setAnimation(String id, int loopCount) {
        return setAnimation(id, loopCount, 1.0f, null);
    }

    public AnimationDesc setAnimation(String id, AnimationListener listener) {
        return setAnimation(id, 1, 1.0f, listener);
    }

    public AnimationDesc setAnimation(String id, int loopCount, AnimationListener listener) {
        return setAnimation(id, loopCount, 1.0f, listener);
    }

    public AnimationDesc setAnimation(String id, int loopCount, float speed, AnimationListener listener) {
        return setAnimation(id, 0.0f, -1.0f, loopCount, speed, listener);
    }

    public AnimationDesc setAnimation(String id, float offset, float duration, int loopCount, float speed, AnimationListener listener) {
        return setAnimation(obtain(id, offset, duration, loopCount, speed, listener));
    }

    protected AnimationDesc setAnimation(Animation anim, float offset, float duration, int loopCount, float speed, AnimationListener listener) {
        return setAnimation(obtain(anim, offset, duration, loopCount, speed, listener));
    }

    protected AnimationDesc setAnimation(AnimationDesc anim) {
        AnimationDesc animationDesc = this.current;
        if (animationDesc == null) {
            this.current = anim;
        } else {
            if (!this.allowSameAnimation && anim != null && animationDesc.animation == anim.animation) {
                anim.time = this.current.time;
            } else {
                removeAnimation(this.current.animation);
            }
            this.animationPool.free(this.current);
            this.current = anim;
        }
        this.justChangedAnimation = true;
        return anim;
    }

    public AnimationDesc animate(String id, float transitionTime) {
        return animate(id, 1, 1.0f, null, transitionTime);
    }

    public AnimationDesc animate(String id, AnimationListener listener, float transitionTime) {
        return animate(id, 1, 1.0f, listener, transitionTime);
    }

    public AnimationDesc animate(String id, int loopCount, AnimationListener listener, float transitionTime) {
        return animate(id, loopCount, 1.0f, listener, transitionTime);
    }

    public AnimationDesc animate(String id, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return animate(id, 0.0f, -1.0f, loopCount, speed, listener, transitionTime);
    }

    public AnimationDesc animate(String id, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return animate(obtain(id, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc animate(Animation anim, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return animate(obtain(anim, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc animate(AnimationDesc anim, float transitionTime) {
        AnimationDesc animationDesc = this.current;
        if (animationDesc == null || animationDesc.loopCount == 0) {
            this.current = anim;
        } else if (this.inAction) {
            queue(anim, transitionTime);
        } else if (!this.allowSameAnimation && anim != null && this.current.animation == anim.animation) {
            anim.time = this.current.time;
            this.animationPool.free(this.current);
            this.current = anim;
        } else {
            AnimationDesc animationDesc2 = this.previous;
            if (animationDesc2 != null) {
                removeAnimation(animationDesc2.animation);
                this.animationPool.free(this.previous);
            }
            this.previous = this.current;
            this.current = anim;
            this.transitionCurrentTime = 0.0f;
            this.transitionTargetTime = transitionTime;
        }
        return anim;
    }

    public AnimationDesc queue(String id, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return queue(id, 0.0f, -1.0f, loopCount, speed, listener, transitionTime);
    }

    public AnimationDesc queue(String id, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return queue(obtain(id, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc queue(Animation anim, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return queue(obtain(anim, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc queue(AnimationDesc anim, float transitionTime) {
        AnimationDesc animationDesc = this.current;
        if (animationDesc == null || animationDesc.loopCount == 0) {
            animate(anim, transitionTime);
        } else {
            AnimationDesc animationDesc2 = this.queued;
            if (animationDesc2 != null) {
                this.animationPool.free(animationDesc2);
            }
            this.queued = anim;
            this.queuedTransitionTime = transitionTime;
            if (this.current.loopCount < 0) {
                this.current.loopCount = 1;
            }
        }
        return anim;
    }

    public AnimationDesc action(String id, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return action(id, 0.0f, -1.0f, loopCount, speed, listener, transitionTime);
    }

    public AnimationDesc action(String id, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return action(obtain(id, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc action(Animation anim, float offset, float duration, int loopCount, float speed, AnimationListener listener, float transitionTime) {
        return action(obtain(anim, offset, duration, loopCount, speed, listener), transitionTime);
    }

    protected AnimationDesc action(AnimationDesc anim, float transitionTime) {
        if (anim.loopCount < 0) {
            throw new GdxRuntimeException("An action cannot be continuous");
        }
        AnimationDesc animationDesc = this.current;
        if (animationDesc == null || animationDesc.loopCount == 0) {
            animate(anim, transitionTime);
        } else {
            AnimationDesc toQueue = this.inAction ? null : obtain(this.current);
            this.inAction = false;
            animate(anim, transitionTime);
            this.inAction = true;
            if (toQueue != null) {
                queue(toQueue, transitionTime);
            }
        }
        return anim;
    }
}