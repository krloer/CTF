package com.kotcrab.vis.ui.util.form;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.util.Validators;
import com.kotcrab.vis.ui.widget.VisCheckBox;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import java.util.Iterator;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class SimpleFormValidator {
    private Array<CheckedButtonWrapper> buttons;
    private ChangeSharedListener changeListener;
    private Array<Disableable> disableTargets;
    private String errorMsgText;
    private Array<VisValidatableTextField> fields;
    private boolean formInvalid;
    private Label messageLabel;
    private FormValidatorStyle style;
    private String successMsg;
    private boolean treatDisabledFieldsAsValid;

    public SimpleFormValidator(Disableable targetToDisable) {
        this(targetToDisable, (Label) null, "default");
    }

    public SimpleFormValidator(Disableable targetToDisable, Label messageLabel) {
        this(targetToDisable, messageLabel, "default");
    }

    public SimpleFormValidator(Disableable targetToDisable, Label messageLabel, String styleName) {
        this(targetToDisable, messageLabel, (FormValidatorStyle) VisUI.getSkin().get(styleName, FormValidatorStyle.class));
    }

    public SimpleFormValidator(Disableable targetToDisable, Label messageLabel, FormValidatorStyle style) {
        this.changeListener = new ChangeSharedListener();
        this.fields = new Array<>();
        this.buttons = new Array<>();
        this.formInvalid = false;
        this.errorMsgText = BuildConfig.FLAVOR;
        this.disableTargets = new Array<>();
        this.treatDisabledFieldsAsValid = true;
        this.style = style;
        if (targetToDisable != null) {
            this.disableTargets.add(targetToDisable);
        }
        this.messageLabel = messageLabel;
    }

    public FormInputValidator notEmpty(VisValidatableTextField field, String errorMsg) {
        EmptyInputValidator validator = new EmptyInputValidator(errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator integerNumber(VisValidatableTextField field, String errorMsg) {
        ValidatorWrapper wrapper = new ValidatorWrapper(errorMsg, Validators.INTEGERS);
        field.addValidator(wrapper);
        add(field);
        return wrapper;
    }

    public FormInputValidator floatNumber(VisValidatableTextField field, String errorMsg) {
        ValidatorWrapper wrapper = new ValidatorWrapper(errorMsg, Validators.FLOATS);
        field.addValidator(wrapper);
        add(field);
        return wrapper;
    }

    public FormInputValidator valueGreaterThan(VisValidatableTextField field, String errorMsg, float value) {
        return valueGreaterThan(field, errorMsg, value, false);
    }

    public FormInputValidator valueLesserThan(VisValidatableTextField field, String errorMsg, float value) {
        return valueLesserThan(field, errorMsg, value, false);
    }

    public FormInputValidator valueGreaterThan(VisValidatableTextField field, String errorMsg, float value, boolean validIfEqualsValue) {
        ValidatorWrapper wrapper = new ValidatorWrapper(errorMsg, new Validators.GreaterThanValidator(value, validIfEqualsValue));
        field.addValidator(wrapper);
        add(field);
        return wrapper;
    }

    public FormInputValidator valueLesserThan(VisValidatableTextField field, String errorMsg, float value, boolean validIfEqualsValue) {
        ValidatorWrapper wrapper = new ValidatorWrapper(errorMsg, new Validators.LesserThanValidator(value, validIfEqualsValue));
        field.addValidator(wrapper);
        add(field);
        return wrapper;
    }

    public FormInputValidator custom(VisValidatableTextField field, FormInputValidator customValidator) {
        field.addValidator(customValidator);
        add(field);
        return customValidator;
    }

    public void checked(Button button, String errorMsg) {
        this.buttons.add(new CheckedButtonWrapper(button, true, errorMsg));
        button.addListener(this.changeListener);
        validate();
    }

    public void unchecked(Button button, String errorMsg) {
        this.buttons.add(new CheckedButtonWrapper(button, false, errorMsg));
        button.addListener(this.changeListener);
        validate();
    }

    public void add(VisValidatableTextField field) {
        if (!this.fields.contains(field, true)) {
            this.fields.add(field);
        }
        field.addListener(this.changeListener);
        validate();
    }

    public void addDisableTarget(Disableable disableable) {
        this.disableTargets.add(disableable);
        updateWidgets();
    }

    public boolean removeDisableTarget(Disableable disableable) {
        boolean result = this.disableTargets.removeValue(disableable, true);
        updateWidgets();
        return result;
    }

    public void setMessageLabel(Label messageLabel) {
        this.messageLabel = messageLabel;
        updateWidgets();
    }

    public void setSuccessMessage(String successMsg) {
        this.successMsg = successMsg;
        updateWidgets();
    }

    public boolean isTreatDisabledFieldsAsValid() {
        return this.treatDisabledFieldsAsValid;
    }

    public void setTreatDisabledFieldsAsValid(boolean treatDisabledFieldAsValid) {
        this.treatDisabledFieldsAsValid = treatDisabledFieldAsValid;
        validate();
    }

    public void validate() {
        this.formInvalid = false;
        this.errorMsgText = null;
        Iterator it = this.buttons.iterator();
        while (it.hasNext()) {
            CheckedButtonWrapper wrapper = (CheckedButtonWrapper) it.next();
            if (wrapper.button.isChecked() != wrapper.mustBeChecked) {
                wrapper.setButtonStateInvalid(true);
            } else {
                wrapper.setButtonStateInvalid(false);
            }
        }
        Iterator it2 = this.buttons.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            CheckedButtonWrapper wrapper2 = (CheckedButtonWrapper) it2.next();
            if (!this.treatDisabledFieldsAsValid || !wrapper2.button.isDisabled()) {
                if (wrapper2.button.isChecked() != wrapper2.mustBeChecked) {
                    this.errorMsgText = wrapper2.errorMsg;
                    this.formInvalid = true;
                    break;
                }
            }
        }
        Iterator it3 = this.fields.iterator();
        while (it3.hasNext()) {
            ((VisValidatableTextField) it3.next()).validateInput();
        }
        Iterator it4 = this.fields.iterator();
        while (true) {
            if (!it4.hasNext()) {
                break;
            }
            VisValidatableTextField field = (VisValidatableTextField) it4.next();
            if (!this.treatDisabledFieldsAsValid || !field.isDisabled()) {
                if (!field.isInputValid()) {
                    Array<InputValidator> validators = field.getValidators();
                    Iterator it5 = validators.iterator();
                    while (true) {
                        if (!it5.hasNext()) {
                            break;
                        }
                        InputValidator v = (InputValidator) it5.next();
                        if (!(v instanceof FormInputValidator)) {
                            throw new IllegalStateException("Fields validated by FormValidator cannot have validators not added using FormValidator methods. Are you adding validators to field manually?");
                        }
                        FormInputValidator validator = (FormInputValidator) v;
                        if (!validator.getLastResult()) {
                            if (!validator.isHideErrorOnEmptyInput() || !field.getText().equals(BuildConfig.FLAVOR)) {
                                this.errorMsgText = validator.getErrorMsg();
                            }
                            this.formInvalid = true;
                        }
                    }
                }
            }
        }
        updateWidgets();
    }

    private void updateWidgets() {
        Iterator it = this.disableTargets.iterator();
        while (it.hasNext()) {
            Disableable disableable = (Disableable) it.next();
            disableable.setDisabled(this.formInvalid);
        }
        Label label = this.messageLabel;
        if (label != null) {
            String str = this.errorMsgText;
            if (str != null) {
                label.setText(str);
            } else {
                label.setText(this.successMsg);
            }
            Color targetColor = this.errorMsgText != null ? this.style.errorLabelColor : this.style.validLabelColor;
            if (targetColor != null && this.style.colorTransitionDuration != 0.0f) {
                this.messageLabel.addAction(Actions.color(targetColor, this.style.colorTransitionDuration));
            } else {
                this.messageLabel.setColor(targetColor);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ChangeSharedListener extends ChangeListener {
        private ChangeSharedListener() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
        public void changed(ChangeListener.ChangeEvent event, Actor actor) {
            SimpleFormValidator.this.validate();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class CheckedButtonWrapper {
        public Button button;
        public String errorMsg;
        public boolean mustBeChecked;

        public CheckedButtonWrapper(Button button, boolean mustBeChecked, String errorMsg) {
            this.button = button;
            this.mustBeChecked = mustBeChecked;
            this.errorMsg = errorMsg;
        }

        public void setButtonStateInvalid(boolean state) {
            Button button = this.button;
            if (button instanceof VisCheckBox) {
                ((VisCheckBox) button).setStateInvalid(state);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class EmptyInputValidator extends FormInputValidator {
        public EmptyInputValidator(String errorMsg) {
            super(errorMsg);
        }

        @Override // com.kotcrab.vis.ui.util.form.FormInputValidator
        public boolean validate(String input) {
            return !input.isEmpty();
        }
    }

    /* loaded from: classes.dex */
    public static class FormValidatorStyle {
        public float colorTransitionDuration;
        public Color errorLabelColor;
        public Color validLabelColor;

        public FormValidatorStyle() {
        }

        public FormValidatorStyle(Color errorLabelColor, Color validLabelColor) {
            this.errorLabelColor = errorLabelColor;
            this.validLabelColor = validLabelColor;
        }

        public FormValidatorStyle(FormValidatorStyle style) {
            this.errorLabelColor = style.errorLabelColor;
            this.validLabelColor = style.validLabelColor;
            this.colorTransitionDuration = style.colorTransitionDuration;
        }
    }
}