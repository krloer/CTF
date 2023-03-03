package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.widget.VisTextField;
import java.util.Iterator;

/* loaded from: classes.dex */
public class VisValidatableTextField extends VisTextField {
    private String lastValid;
    private LastValidFocusListener restoreFocusListener;
    private boolean restoreLastValid;
    private boolean validationEnabled;
    private Array<InputValidator> validators;

    public VisValidatableTextField() {
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        init();
    }

    public VisValidatableTextField(String text) {
        super(text);
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        init();
    }

    public VisValidatableTextField(String text, String styleName) {
        super(text, styleName);
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        init();
    }

    public VisValidatableTextField(String text, VisTextField.VisTextFieldStyle style) {
        super(text, style);
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        init();
    }

    public VisValidatableTextField(InputValidator validator) {
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        addValidator(validator);
        init();
    }

    public VisValidatableTextField(InputValidator... validators) {
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        for (InputValidator validator : validators) {
            addValidator(validator);
        }
        init();
    }

    public VisValidatableTextField(boolean restoreLastValid, InputValidator validator) {
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        addValidator(validator);
        init();
        setRestoreLastValid(restoreLastValid);
    }

    public VisValidatableTextField(boolean restoreLastValid, InputValidator... validators) {
        this.validators = new Array<>();
        this.validationEnabled = true;
        this.restoreLastValid = false;
        for (InputValidator validator : validators) {
            addValidator(validator);
        }
        init();
        setRestoreLastValid(restoreLastValid);
    }

    private void init() {
        setProgrammaticChangeEvents(true);
        setIgnoreEqualsTextChange(false);
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    void beforeChangeEventFired() {
        validateInput();
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void setText(String str) {
        super.setText(str);
        validateInput();
    }

    public void validateInput() {
        if (this.validationEnabled) {
            Iterator it = this.validators.iterator();
            while (it.hasNext()) {
                InputValidator validator = (InputValidator) it.next();
                if (!validator.validateInput(getText())) {
                    setInputValid(false);
                    return;
                }
            }
        }
        setInputValid(true);
    }

    public void addValidator(InputValidator validator) {
        this.validators.add(validator);
        validateInput();
    }

    public Array<InputValidator> getValidators() {
        return this.validators;
    }

    public boolean isValidationEnabled() {
        return this.validationEnabled;
    }

    public void setValidationEnabled(boolean validationEnabled) {
        this.validationEnabled = validationEnabled;
        validateInput();
    }

    public boolean isRestoreLastValid() {
        return this.restoreLastValid;
    }

    public void setRestoreLastValid(boolean restoreLastValid) {
        if (this.hasSelection) {
            throw new IllegalStateException("Last valid text restore can't be changed while filed has selection");
        }
        this.restoreLastValid = restoreLastValid;
        if (restoreLastValid) {
            if (this.restoreFocusListener == null) {
                this.restoreFocusListener = new LastValidFocusListener();
            }
            addListener(this.restoreFocusListener);
            return;
        }
        removeListener(this.restoreFocusListener);
    }

    public void restoreLastValidText() {
        if (this.restoreLastValid) {
            super.setText(this.lastValid);
            setInputValid(true);
            return;
        }
        throw new IllegalStateException("Restore last valid is not enabled, see #setRestoreLastValid(boolean)");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class LastValidFocusListener extends FocusListener {
        private LastValidFocusListener() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
        public void keyboardFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
            if (focused && VisValidatableTextField.this.restoreLastValid) {
                VisValidatableTextField visValidatableTextField = VisValidatableTextField.this;
                visValidatableTextField.lastValid = visValidatableTextField.getText();
            }
            if (!focused && !VisValidatableTextField.this.isInputValid() && VisValidatableTextField.this.restoreLastValid) {
                VisValidatableTextField.this.restoreLastValidText();
            }
        }
    }
}