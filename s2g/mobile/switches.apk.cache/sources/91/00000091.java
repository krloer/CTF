package com.badlogic.gdx.backends.android;

import android.media.AudioRecord;
import com.badlogic.gdx.audio.AudioRecorder;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public class AndroidAudioRecorder implements AudioRecorder {
    private AudioRecord recorder;

    public AndroidAudioRecorder(int samplingRate, boolean isMono) {
        int channelConfig = isMono ? 16 : 12;
        int minBufferSize = AudioRecord.getMinBufferSize(samplingRate, channelConfig, 2);
        this.recorder = new AudioRecord(1, samplingRate, channelConfig, 2, minBufferSize);
        if (this.recorder.getState() != 1) {
            throw new GdxRuntimeException("Unable to initialize AudioRecorder.\nDo you have the RECORD_AUDIO permission?");
        }
        this.recorder.startRecording();
    }

    @Override // com.badlogic.gdx.audio.AudioRecorder, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.recorder.stop();
        this.recorder.release();
    }

    @Override // com.badlogic.gdx.audio.AudioRecorder
    public void read(short[] samples, int offset, int numSamples) {
        int read = 0;
        while (read != numSamples) {
            read += this.recorder.read(samples, offset + read, numSamples - read);
        }
    }
}