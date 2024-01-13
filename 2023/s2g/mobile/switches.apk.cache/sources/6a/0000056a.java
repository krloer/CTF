package com.kotcrab.vis.ui.util.form;

import com.kotcrab.vis.ui.util.InputValidator;

/* loaded from: classes.dex */
public class ValidatorWrapper extends FormInputValidator {
    private InputValidator validator;

    public ValidatorWrapper(String errorMsg, InputValidator validator) {
        super(errorMsg);
        this.validator = validator;
    }

    @Override // com.kotcrab.vis.ui.util.form.FormInputValidator
    protected boolean validate(String input) {
        return this.validator.validateInput(input);
    }
}