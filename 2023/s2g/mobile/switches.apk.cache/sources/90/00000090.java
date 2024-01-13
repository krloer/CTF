package com.badlogic.gdx.backends.android;

import android.media.AudioTrack;
import com.badlogic.gdx.audio.AudioDevice;
import com.badlogic.gdx.graphics.GL20;

/* loaded from: classes.dex */
class AndroidAudioDevice implements AudioDevice {
    private short[] buffer = new short[GL20.GL_STENCIL_BUFFER_BIT];
    private final boolean isMono;
    private final int latency;
    private final AudioTrack track;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AndroidAudioDevice(int samplingRate, boolean isMono) {
        this.isMono = isMono;
        int minSize = AudioTrack.getMinBufferSize(samplingRate, isMono ? 4 : 12, 2);
        this.track = new AudioTrack(3, samplingRate, isMono ? 4 : 12, 2, minSize, 1);
        this.track.play();
        this.latency = minSize / (isMono ? 1 : 2);
    }

    @Override // com.badlogic.gdx.audio.AudioDevice, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.track.stop();
        this.track.release();
    }

    @Override // com.badlogic.gdx.audio.AudioDevice
    public boolean isMono() {
        return this.isMono;
    }

    @Override // com.badlogic.gdx.audio.AudioDevice
    public void writeSamples(short[] samples, int offset, int numSamples) {
        int writtenSamples = this.track.write(samples, offset, numSamples);
        while (writtenSamples != numSamples) {
            writtenSamples += this.track.write(samples, offset + writtenSamples, numSamples - writtenSamples);
        }
    }

    @Override // com.badlogic.gdx.audio.AudioDevice
    public void writeSamples(float[] samples, int offset, int numSamples) {
        if (this.buffer.length < samples.length) {
            this.buffer = new short[samples.length];
        }
        int bound = offset + numSamples;
        int i = offset;
        int j = 0;
        while (i < bound) {
            float fValue = samples[i];
            if (fValue > 1.0f) {
                fValue = 1.0f;
            }
            if (fValue < -1.0f) {
                fValue = -1.0f;
            }
            short value = (short) (32767.0f * fValue);
            this.buffer[j] = value;
            i++;
            j++;
        }
        int writtenSamples = this.track.write(this.buffer, 0, numSamples);
        while (writtenSamples != numSamples) {
            writtenSamples += this.track.write(this.buffer, writtenSamples, numSamples - writtenSamples);
        }
    }

    @Override // com.badlogic.gdx.audio.AudioDevice
    public int getLatency() {
        return this.latency;
    }

    @Override // com.badlogic.gdx.audio.AudioDevice
    public void setVolume(float volume) {
        this.track.setStereoVolume(volume, volume);
    }
}