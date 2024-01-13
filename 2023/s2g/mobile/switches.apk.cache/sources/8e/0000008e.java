package com.badlogic.gdx.backends.android;

import android.util.Log;
import com.badlogic.gdx.ApplicationLogger;

/* loaded from: classes.dex */
public class AndroidApplicationLogger implements ApplicationLogger {
    @Override // com.badlogic.gdx.ApplicationLogger
    public void log(String tag, String message) {
        Log.i(tag, message);
    }

    @Override // com.badlogic.gdx.ApplicationLogger
    public void log(String tag, String message, Throwable exception) {
        Log.i(tag, message, exception);
    }

    @Override // com.badlogic.gdx.ApplicationLogger
    public void error(String tag, String message) {
        Log.e(tag, message);
    }

    @Override // com.badlogic.gdx.ApplicationLogger
    public void error(String tag, String message, Throwable exception) {
        Log.e(tag, message, exception);
    }

    @Override // com.badlogic.gdx.ApplicationLogger
    public void debug(String tag, String message) {
        Log.d(tag, message);
    }

    @Override // com.badlogic.gdx.ApplicationLogger
    public void debug(String tag, String message, Throwable exception) {
        Log.d(tag, message, exception);
    }
}