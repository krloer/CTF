package com.badlogic.gdx.backends.android;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import com.badlogic.gdx.audio.Sound;
import com.badlogic.gdx.files.FileHandle;

/* loaded from: classes.dex */
public class AsynchronousAndroidAudio extends DefaultAndroidAudio {
    private final Handler handler;
    private final HandlerThread handlerThread;

    public AsynchronousAndroidAudio(Context context, AndroidApplicationConfiguration config) {
        super(context, config);
        if (!config.disableAudio) {
            this.handlerThread = new HandlerThread("libGDX Sound Management");
            this.handlerThread.start();
            this.handler = new Handler(this.handlerThread.getLooper());
            return;
        }
        this.handler = null;
        this.handlerThread = null;
    }

    @Override // com.badlogic.gdx.backends.android.DefaultAndroidAudio, com.badlogic.gdx.utils.Disposable
    public void dispose() {
        super.dispose();
        HandlerThread handlerThread = this.handlerThread;
        if (handlerThread != null) {
            handlerThread.quit();
        }
    }

    @Override // com.badlogic.gdx.backends.android.DefaultAndroidAudio, com.badlogic.gdx.Audio
    public Sound newSound(FileHandle file) {
        Sound sound = super.newSound(file);
        return new AsynchronousSound(sound, this.handler);
    }
}