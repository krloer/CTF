package com.badlogic.gdx.utils;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* loaded from: classes.dex */
public class AtomicQueue<T> {
    private final AtomicReferenceArray<T> queue;
    private final AtomicInteger writeIndex = new AtomicInteger();
    private final AtomicInteger readIndex = new AtomicInteger();

    public AtomicQueue(int capacity) {
        this.queue = new AtomicReferenceArray<>(capacity);
    }

    private int next(int idx) {
        return (idx + 1) % this.queue.length();
    }

    public boolean put(T value) {
        int write = this.writeIndex.get();
        int read = this.readIndex.get();
        int next = next(write);
        if (next == read) {
            return false;
        }
        this.queue.set(write, value);
        this.writeIndex.set(next);
        return true;
    }

    public T poll() {
        int read = this.readIndex.get();
        int write = this.writeIndex.get();
        if (read == write) {
            return null;
        }
        T value = this.queue.get(read);
        this.readIndex.set(next(read));
        return value;
    }
}