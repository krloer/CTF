package com.kotcrab.vis.ui.widget.file.internal;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes.dex */
public class ServiceThreadFactory implements ThreadFactory {
    private final AtomicLong count = new AtomicLong(0);
    private final String threadPrefix;

    public ServiceThreadFactory(String threadPrefix) {
        this.threadPrefix = threadPrefix + "-";
    }

    @Override // java.util.concurrent.ThreadFactory
    public Thread newThread(Runnable runnable) {
        Thread thread = Executors.defaultThreadFactory().newThread(runnable);
        thread.setName(this.threadPrefix + this.count.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    }
}