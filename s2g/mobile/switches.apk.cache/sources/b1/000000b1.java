package com.badlogic.gdx.backends.android;

import android.media.AudioManager;
import android.media.SoundPool;
import com.badlogic.gdx.audio.Sound;
import com.badlogic.gdx.utils.IntArray;

/* loaded from: classes.dex */
final class AndroidSound implements Sound {
    final AudioManager manager;
    final int soundId;
    final SoundPool soundPool;
    final IntArray streamIds = new IntArray(8);

    /* JADX INFO: Access modifiers changed from: package-private */
    public AndroidSound(SoundPool pool, AudioManager manager, int soundId) {
        this.soundPool = pool;
        this.manager = manager;
        this.soundId = soundId;
    }

    @Override // com.badlogic.gdx.audio.Sound, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.soundPool.unload(this.soundId);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play() {
        return play(1.0f);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play(float volume) {
        if (this.streamIds.size == 8) {
            this.streamIds.pop();
        }
        int streamId = this.soundPool.play(this.soundId, volume, volume, 1, 0, 1.0f);
        if (streamId == 0) {
            return -1L;
        }
        this.streamIds.insert(0, streamId);
        return streamId;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void stop() {
        int n = this.streamIds.size;
        for (int i = 0; i < n; i++) {
            this.soundPool.stop(this.streamIds.get(i));
        }
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void stop(long soundId) {
        this.soundPool.stop((int) soundId);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void pause() {
        this.soundPool.autoPause();
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void pause(long soundId) {
        this.soundPool.pause((int) soundId);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void resume() {
        this.soundPool.autoResume();
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void resume(long soundId) {
        this.soundPool.resume((int) soundId);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setPitch(long soundId, float pitch) {
        this.soundPool.setRate((int) soundId, pitch);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setVolume(long soundId, float volume) {
        this.soundPool.setVolume((int) soundId, volume, volume);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop() {
        return loop(1.0f);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop(float volume) {
        if (this.streamIds.size == 8) {
            this.streamIds.pop();
        }
        int streamId = this.soundPool.play(this.soundId, volume, volume, 1, -1, 1.0f);
        if (streamId == 0) {
            return -1L;
        }
        this.streamIds.insert(0, streamId);
        return streamId;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setLooping(long soundId, boolean looping) {
        int streamId = (int) soundId;
        this.soundPool.pause(streamId);
        this.soundPool.setLoop(streamId, looping ? -1 : 0);
        this.soundPool.resume(streamId);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public void setPan(long soundId, float pan, float volume) {
        float leftVolume = volume;
        float rightVolume = volume;
        if (pan < 0.0f) {
            rightVolume *= 1.0f - Math.abs(pan);
        } else if (pan > 0.0f) {
            leftVolume *= 1.0f - Math.abs(pan);
        }
        this.soundPool.setVolume((int) soundId, leftVolume, rightVolume);
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long play(float volume, float pitch, float pan) {
        if (this.streamIds.size == 8) {
            this.streamIds.pop();
        }
        float leftVolume = volume;
        float rightVolume = volume;
        if (pan < 0.0f) {
            rightVolume *= 1.0f - Math.abs(pan);
        } else if (pan > 0.0f) {
            leftVolume *= 1.0f - Math.abs(pan);
        }
        int streamId = this.soundPool.play(this.soundId, leftVolume, rightVolume, 1, 0, pitch);
        if (streamId == 0) {
            return -1L;
        }
        this.streamIds.insert(0, streamId);
        return streamId;
    }

    @Override // com.badlogic.gdx.audio.Sound
    public long loop(float volume, float pitch, float pan) {
        if (this.streamIds.size == 8) {
            this.streamIds.pop();
        }
        float leftVolume = volume;
        float rightVolume = volume;
        if (pan < 0.0f) {
            rightVolume *= 1.0f - Math.abs(pan);
        } else if (pan > 0.0f) {
            leftVolume *= 1.0f - Math.abs(pan);
        }
        int streamId = this.soundPool.play(this.soundId, leftVolume, rightVolume, 1, -1, pitch);
        if (streamId == 0) {
            return -1L;
        }
        this.streamIds.insert(0, streamId);
        return streamId;
    }
}