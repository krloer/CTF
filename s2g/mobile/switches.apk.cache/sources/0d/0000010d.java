package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.reflect.ArrayReflection;

/* loaded from: classes.dex */
public class Animation<T> {
    private float animationDuration;
    private float frameDuration;
    T[] keyFrames;
    private int lastFrameNumber;
    private float lastStateTime;
    private PlayMode playMode;

    /* loaded from: classes.dex */
    public enum PlayMode {
        NORMAL,
        REVERSED,
        LOOP,
        LOOP_REVERSED,
        LOOP_PINGPONG,
        LOOP_RANDOM
    }

    /* JADX WARN: Multi-variable type inference failed */
    public Animation(float frameDuration, Array<? extends T> keyFrames) {
        this.playMode = PlayMode.NORMAL;
        this.frameDuration = frameDuration;
        Class arrayType = keyFrames.items.getClass().getComponentType();
        Object[] objArr = (Object[]) ArrayReflection.newInstance(arrayType, keyFrames.size);
        int n = keyFrames.size;
        for (int i = 0; i < n; i++) {
            objArr[i] = keyFrames.get(i);
        }
        setKeyFrames(objArr);
    }

    public Animation(float frameDuration, Array<? extends T> keyFrames, PlayMode playMode) {
        this(frameDuration, keyFrames);
        setPlayMode(playMode);
    }

    public Animation(float frameDuration, T... keyFrames) {
        this.playMode = PlayMode.NORMAL;
        this.frameDuration = frameDuration;
        setKeyFrames(keyFrames);
    }

    public T getKeyFrame(float stateTime, boolean looping) {
        PlayMode oldPlayMode = this.playMode;
        if (looping && (this.playMode == PlayMode.NORMAL || this.playMode == PlayMode.REVERSED)) {
            if (this.playMode == PlayMode.NORMAL) {
                this.playMode = PlayMode.LOOP;
            } else {
                this.playMode = PlayMode.LOOP_REVERSED;
            }
        } else if (!looping && this.playMode != PlayMode.NORMAL && this.playMode != PlayMode.REVERSED) {
            if (this.playMode == PlayMode.LOOP_REVERSED) {
                this.playMode = PlayMode.REVERSED;
            } else {
                this.playMode = PlayMode.LOOP;
            }
        }
        T frame = getKeyFrame(stateTime);
        this.playMode = oldPlayMode;
        return frame;
    }

    public T getKeyFrame(float stateTime) {
        int frameNumber = getKeyFrameIndex(stateTime);
        return this.keyFrames[frameNumber];
    }

    public int getKeyFrameIndex(float stateTime) {
        if (this.keyFrames.length == 1) {
            return 0;
        }
        int frameNumber = (int) (stateTime / this.frameDuration);
        switch (this.playMode) {
            case NORMAL:
                frameNumber = Math.min(this.keyFrames.length - 1, frameNumber);
                break;
            case LOOP:
                frameNumber %= this.keyFrames.length;
                break;
            case LOOP_PINGPONG:
                T[] tArr = this.keyFrames;
                frameNumber %= (tArr.length * 2) - 2;
                if (frameNumber >= tArr.length) {
                    frameNumber = (tArr.length - 2) - (frameNumber - tArr.length);
                    break;
                }
                break;
            case LOOP_RANDOM:
                int lastFrameNumber = (int) (this.lastStateTime / this.frameDuration);
                if (lastFrameNumber != frameNumber) {
                    frameNumber = MathUtils.random(this.keyFrames.length - 1);
                    break;
                } else {
                    frameNumber = this.lastFrameNumber;
                    break;
                }
            case REVERSED:
                frameNumber = Math.max((this.keyFrames.length - frameNumber) - 1, 0);
                break;
            case LOOP_REVERSED:
                T[] tArr2 = this.keyFrames;
                frameNumber = (tArr2.length - (frameNumber % tArr2.length)) - 1;
                break;
        }
        this.lastFrameNumber = frameNumber;
        this.lastStateTime = stateTime;
        return frameNumber;
    }

    public T[] getKeyFrames() {
        return this.keyFrames;
    }

    protected void setKeyFrames(T... keyFrames) {
        this.keyFrames = keyFrames;
        this.animationDuration = keyFrames.length * this.frameDuration;
    }

    public PlayMode getPlayMode() {
        return this.playMode;
    }

    public void setPlayMode(PlayMode playMode) {
        this.playMode = playMode;
    }

    public boolean isAnimationFinished(float stateTime) {
        int frameNumber = (int) (stateTime / this.frameDuration);
        return this.keyFrames.length - 1 < frameNumber;
    }

    public void setFrameDuration(float frameDuration) {
        this.frameDuration = frameDuration;
        this.animationDuration = this.keyFrames.length * frameDuration;
    }

    public float getFrameDuration() {
        return this.frameDuration;
    }

    public float getAnimationDuration() {
        return this.animationDuration;
    }
}