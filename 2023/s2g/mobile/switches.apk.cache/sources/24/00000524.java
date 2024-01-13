package com.kotcrab.vis.ui.util;

import com.kotcrab.vis.ui.widget.VisTextField;

/* loaded from: classes.dex */
public abstract class NumberDigitsTextFieldFilter implements VisTextField.TextFieldFilter {
    private boolean acceptNegativeValues;
    private boolean useFieldCursorPosition;

    public NumberDigitsTextFieldFilter(boolean acceptNegativeValues) {
        this.acceptNegativeValues = acceptNegativeValues;
    }

    public boolean isAcceptNegativeValues() {
        return this.acceptNegativeValues;
    }

    public void setAcceptNegativeValues(boolean acceptNegativeValues) {
        this.acceptNegativeValues = acceptNegativeValues;
    }

    public boolean isUseFieldCursorPosition() {
        return this.useFieldCursorPosition;
    }

    public void setUseFieldCursorPosition(boolean useFieldCursorPosition) {
        this.useFieldCursorPosition = useFieldCursorPosition;
    }
}