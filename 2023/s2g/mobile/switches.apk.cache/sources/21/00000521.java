package com.kotcrab.vis.ui.util;

import com.kotcrab.vis.ui.widget.VisTextField;

/* loaded from: classes.dex */
public class FloatDigitsOnlyFilter extends IntDigitsOnlyFilter {
    public FloatDigitsOnlyFilter(boolean acceptNegativeValues) {
        super(acceptNegativeValues);
    }

    @Override // com.kotcrab.vis.ui.util.IntDigitsOnlyFilter, com.kotcrab.vis.ui.widget.VisTextField.TextFieldFilter
    public boolean acceptChar(VisTextField field, char c) {
        String beforeSelection;
        int selectionStart = field.getSelectionStart();
        int cursorPos = field.getCursorPosition();
        if (field.isTextSelected()) {
            String beforeSelection2 = field.getText().substring(0, Math.min(selectionStart, cursorPos));
            String afterSelection = field.getText().substring(Math.max(selectionStart, cursorPos));
            beforeSelection = beforeSelection2 + afterSelection;
        } else {
            beforeSelection = field.getText();
        }
        if (c != '.' || beforeSelection.contains(".")) {
            return super.acceptChar(field, c);
        }
        return true;
    }
}