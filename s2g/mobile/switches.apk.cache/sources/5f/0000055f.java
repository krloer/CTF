package com.kotcrab.vis.ui.util.form;

import com.kotcrab.vis.ui.util.InputValidator;

/* loaded from: classes.dex */
public abstract class FormInputValidator implements InputValidator {
    private String errorMsg;
    private boolean hideErrorOnEmptyInput = false;
    private boolean result;

    protected abstract boolean validate(String str);

    public FormInputValidator(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    @Override // com.kotcrab.vis.ui.util.InputValidator
    public final boolean validateInput(String input) {
        this.result = validate(input);
        return this.result;
    }

    public FormInputValidator hideErrorOnEmptyInput() {
        this.hideErrorOnEmptyInput = true;
        return this;
    }

    public void setHideErrorOnEmptyInput(boolean hideErrorOnEmptyInput) {
        this.hideErrorOnEmptyInput = hideErrorOnEmptyInput;
    }

    public boolean isHideErrorOnEmptyInput() {
        return this.hideErrorOnEmptyInput;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public String getErrorMsg() {
        return this.errorMsg;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean getLastResult() {
        return this.result;
    }
}