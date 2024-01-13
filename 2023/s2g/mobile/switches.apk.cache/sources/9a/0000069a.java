package com.kotcrab.vis.ui.widget.spinner;

/* loaded from: classes.dex */
public interface SpinnerModel {
    void bind(Spinner spinner);

    boolean decrement();

    boolean decrement(boolean z);

    String getText();

    boolean increment();

    boolean increment(boolean z);

    boolean isWrap();

    void setWrap(boolean z);

    void textChanged();
}