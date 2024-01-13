package com.kotcrab.vis.ui.util;

import com.kotcrab.vis.ui.widget.VisTextField;

/* loaded from: classes.dex */
public class IntDigitsOnlyFilter extends NumberDigitsTextFieldFilter {
    public IntDigitsOnlyFilter(boolean acceptNegativeValues) {
        super(acceptNegativeValues);
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldFilter
    public boolean acceptChar(VisTextField field, char c) {
        if (isAcceptNegativeValues()) {
            if (isUseFieldCursorPosition()) {
                if (c == '-' && (field.getCursorPosition() > 0 || field.getText().startsWith("-"))) {
                    return false;
                }
            } else if (c == '-' && field.getText().startsWith("-")) {
                return false;
            }
            if (c == '-') {
                return true;
            }
        }
        return Character.isDigit(c);
    }
}