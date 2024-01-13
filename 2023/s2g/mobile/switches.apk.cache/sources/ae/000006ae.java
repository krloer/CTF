package com.kotcrab.vis.ui.widget.toast;

import com.kotcrab.vis.ui.widget.VisTable;

/* loaded from: classes.dex */
public class ToastTable extends VisTable {
    protected Toast toast;

    public ToastTable() {
    }

    public ToastTable(boolean setVisDefaults) {
        super(setVisDefaults);
    }

    public void fadeOut() {
        Toast toast = this.toast;
        if (toast == null) {
            throw new IllegalStateException("fadeOut can't be called before toast was shown by ToastManager");
        }
        toast.fadeOut();
    }

    public void setToast(Toast toast) {
        this.toast = toast;
    }

    public Toast getToast() {
        return this.toast;
    }
}