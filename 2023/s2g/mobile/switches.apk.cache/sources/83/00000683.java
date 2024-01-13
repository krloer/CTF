package com.kotcrab.vis.ui.widget.spinner;

/* loaded from: classes.dex */
public abstract class AbstractSpinnerModel implements SpinnerModel {
    private boolean allowRebind;
    protected Spinner spinner;
    private boolean wrap;

    protected abstract boolean decrementModel();

    protected abstract boolean incrementModel();

    public AbstractSpinnerModel(boolean allowRebind) {
        this.allowRebind = allowRebind;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void bind(Spinner spinner) {
        if (this.spinner != null && !this.allowRebind) {
            throw new IllegalStateException("this spinner model can't be reused");
        }
        this.spinner = spinner;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public final boolean increment() {
        return increment(this.spinner.isProgrammaticChangeEvents());
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public final boolean increment(boolean fireEvent) {
        boolean valueChanged = incrementModel();
        if (valueChanged) {
            this.spinner.notifyValueChanged(fireEvent);
        }
        return valueChanged;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public final boolean decrement() {
        return decrement(this.spinner.isProgrammaticChangeEvents());
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public final boolean decrement(boolean fireEvent) {
        boolean valueChanged = decrementModel();
        if (valueChanged) {
            this.spinner.notifyValueChanged(fireEvent);
        }
        return valueChanged;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public boolean isWrap() {
        return this.wrap;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void setWrap(boolean wrap) {
        this.wrap = wrap;
    }

    public boolean isAllowRebind() {
        return this.allowRebind;
    }

    protected void setAllowRebind(boolean allowRebind) {
        this.allowRebind = allowRebind;
    }
}