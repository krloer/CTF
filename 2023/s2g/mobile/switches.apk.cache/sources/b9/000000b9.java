package com.badlogic.gdx.backends.android;

import android.os.Handler;
import com.badlogic.gdx.audio.Sound;

/* loaded from: classes.dex */
public class AsynchronousSound implements Sound {
    private final Handler handler;
    private final Sound sound;

    public AsynchronousSound(Sound sound, Handler handler) {
        this.sound = sound;
        this.handler = handler;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play() {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.1
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.play();
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play(final float volume) {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.2
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.play(volume);
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play(final float volume, final float pitch, final float pan) {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.3
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.play(volume, pitch, pan);
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop() {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.4
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.loop();
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop(final float volume) {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.5
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.loop(volume);
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop(final float volume, final float pitch, final float pan) {
        this.handler.post(new Runnable() { // from class: com.badlogic.gdx.backends.android.AsynchronousSound.6
            @Override // java.lang.Runnable
            public void run() {
                AsynchronousSound.this.sound.loop(volume, pitch, pan);
            }
        });
        return 0L;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void stop() {
        this.sound.stop();
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void pause() {
        this.sound.pause();
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void resume() {
        this.sound.resume();
    }

    @Override // com.badlogic.gdx.audio.Sound, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.sound.dispose();
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void stop(long soundId) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void pause(long soundId) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void resume(long soundId) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setLooping(long soundId, boolean looping) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setPitch(long soundId, float pitch) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setVolume(long soundId, float volume) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setPan(long soundId, float pan, float volume) {
        throw new UnsupportedOperationException("Asynchronous audio doesn't support sound id based operations.");
    }
}