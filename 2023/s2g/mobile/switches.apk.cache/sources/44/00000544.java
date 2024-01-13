package com.kotcrab.vis.ui.util.async;

/* loaded from: classes.dex */
public interface AsyncTaskListener {
    void failed(String str, Exception exc);

    void finished();

    void messageChanged(String str);

    void progressChanged(int i);
}