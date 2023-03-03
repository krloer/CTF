package com.kotcrab.vis.ui.util.async;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.utils.Array;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public abstract class AsyncTask {
    private String threadName;
    private Status status = Status.PENDING;
    private Array<AsyncTaskListener> listeners = new Array<>();

    /* loaded from: classes.dex */
    enum Status {
        PENDING,
        RUNNING,
        FINISHED
    }

    protected abstract void doInBackground() throws Exception;

    public AsyncTask(String threadName) {
        this.threadName = threadName;
    }

    public void execute() {
        if (this.status == Status.RUNNING) {
            throw new IllegalStateException("Task is already running.");
        }
        if (this.status == Status.FINISHED) {
            throw new IllegalStateException("Task has been already executed and can't be reused.");
        }
        this.status = Status.RUNNING;
        new Thread(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.1
            @Override // java.lang.Runnable
            public void run() {
                AsyncTask.this.executeInBackground();
            }
        }, this.threadName).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void executeInBackground() {
        try {
            doInBackground();
        } catch (Exception e) {
            failed(e);
        }
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.2
            @Override // java.lang.Runnable
            public void run() {
                Iterator it = AsyncTask.this.listeners.iterator();
                while (it.hasNext()) {
                    AsyncTaskListener listener = (AsyncTaskListener) it.next();
                    listener.finished();
                }
                AsyncTask.this.status = Status.FINISHED;
            }
        });
    }

    protected void failed(String message) {
        failed(message, new IllegalStateException(message));
    }

    protected void failed(Exception exception) {
        failed(exception.getMessage(), exception);
    }

    protected void failed(final String message, final Exception exception) {
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.3
            @Override // java.lang.Runnable
            public void run() {
                Iterator it = AsyncTask.this.listeners.iterator();
                while (it.hasNext()) {
                    AsyncTaskListener listener = (AsyncTaskListener) it.next();
                    listener.failed(message, exception);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setProgressPercent(final int progressPercent) {
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.4
            @Override // java.lang.Runnable
            public void run() {
                Iterator it = AsyncTask.this.listeners.iterator();
                while (it.hasNext()) {
                    AsyncTaskListener listener = (AsyncTaskListener) it.next();
                    listener.progressChanged(progressPercent);
                }
            }
        });
    }

    protected void setMessage(final String message) {
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.5
            @Override // java.lang.Runnable
            public void run() {
                Iterator it = AsyncTask.this.listeners.iterator();
                while (it.hasNext()) {
                    AsyncTaskListener listener = (AsyncTaskListener) it.next();
                    listener.messageChanged(message);
                }
            }
        });
    }

    protected void executeOnGdx(final Runnable runnable) {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Exception> exceptionAt = new AtomicReference<>();
        Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.util.async.AsyncTask.6
            @Override // java.lang.Runnable
            public void run() {
                try {
                    try {
                        runnable.run();
                    } catch (Exception e) {
                        exceptionAt.set(e);
                    }
                } finally {
                    latch.countDown();
                }
            }
        });
        try {
            latch.await();
            Exception e = exceptionAt.get();
            if (e != null) {
                failed(e);
            }
        } catch (InterruptedException e2) {
            failed(e2);
        }
    }

    public void addListener(AsyncTaskListener listener) {
        this.listeners.add(listener);
    }

    public boolean removeListener(AsyncTaskListener listener) {
        return this.listeners.removeValue(listener, true);
    }

    public String getThreadName() {
        return this.threadName;
    }

    public Status getStatus() {
        return this.status;
    }
}