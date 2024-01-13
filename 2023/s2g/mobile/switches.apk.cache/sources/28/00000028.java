package com.badlogic.ashley.signals;

import com.badlogic.gdx.utils.SnapshotArray;

/* loaded from: classes.dex */
public class Signal<T> {
    private SnapshotArray<Listener<T>> listeners = new SnapshotArray<>();

    public void add(Listener<T> listener) {
        this.listeners.add(listener);
    }

    public void remove(Listener<T> listener) {
        this.listeners.removeValue(listener, true);
    }

    public void removeAllListeners() {
        this.listeners.clear();
    }

    public void dispatch(T object) {
        Object[] items = this.listeners.begin();
        int n = this.listeners.size;
        for (int i = 0; i < n; i++) {
            Listener<T> listener = (Listener) items[i];
            listener.receive(this, object);
        }
        this.listeners.end();
    }
}