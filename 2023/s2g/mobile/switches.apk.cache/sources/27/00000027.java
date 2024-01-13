package com.badlogic.ashley.signals;

/* loaded from: classes.dex */
public interface Listener<T> {
    void receive(Signal<T> signal, T t);
}