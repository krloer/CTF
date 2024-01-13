package com.badlogic.gdx.utils.async;

import com.badlogic.gdx.utils.GdxRuntimeException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/* loaded from: classes.dex */
public class AsyncResult<T> {
    private final Future<T> future;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AsyncResult(Future<T> future) {
        this.future = future;
    }

    public boolean isDone() {
        return this.future.isDone();
    }

    public T get() {
        try {
            return this.future.get();
        } catch (InterruptedException e) {
            return null;
        } catch (ExecutionException ex) {
            throw new GdxRuntimeException(ex.getCause());
        }
    }
}