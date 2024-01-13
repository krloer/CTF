package com.badlogic.gdx.utils.async;

import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.LongCompanionObject;

/* loaded from: classes.dex */
public class AsyncExecutor implements Disposable {
    private final ExecutorService executor;

    public AsyncExecutor(int maxConcurrent) {
        this(maxConcurrent, "AsynchExecutor-Thread");
    }

    public AsyncExecutor(int maxConcurrent, final String name) {
        this.executor = Executors.newFixedThreadPool(maxConcurrent, new ThreadFactory() { // from class: com.badlogic.gdx.utils.async.AsyncExecutor.1
            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, name);
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    public <T> AsyncResult<T> submit(final AsyncTask<T> task) {
        if (this.executor.isShutdown()) {
            throw new GdxRuntimeException("Cannot run tasks on an executor that has been shutdown (disposed)");
        }
        return new AsyncResult<>(this.executor.submit(new Callable<T>() { // from class: com.badlogic.gdx.utils.async.AsyncExecutor.2
            /* JADX WARN: Type inference failed for: r0v1, types: [T, java.lang.Object] */
            @Override // java.util.concurrent.Callable
            public T call() throws Exception {
                return task.call();
            }
        }));
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.executor.shutdown();
        try {
            this.executor.awaitTermination(LongCompanionObject.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new GdxRuntimeException("Couldn't shutdown loading thread", e);
        }
    }
}