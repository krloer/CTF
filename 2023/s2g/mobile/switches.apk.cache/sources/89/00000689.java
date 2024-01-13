package com.kotcrab.vis.ui.widget.spinner;

import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.util.IntDigitsOnlyFilter;
import com.kotcrab.vis.ui.util.Validators;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class IntSpinnerModel extends AbstractSpinnerModel {
    private BoundsValidator boundsValidator;
    private int current;
    private int max;
    private int min;
    private int step;
    private IntDigitsOnlyFilter textFieldFilter;

    public IntSpinnerModel(int initialValue, int min, int max) {
        this(initialValue, min, max, 1);
    }

    public IntSpinnerModel(int initialValue, int min, int max, int step) {
        super(false);
        this.boundsValidator = new BoundsValidator();
        if (min > max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        if (step <= 0) {
            throw new IllegalArgumentException("step must be > 0");
        }
        this.current = initialValue;
        this.max = max;
        this.min = min;
        this.step = step;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel, com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void bind(Spinner spinner) {
        super.bind(spinner);
        VisValidatableTextField valueText = spinner.getTextField();
        valueText.getValidators().clear();
        valueText.addValidator(this.boundsValidator);
        valueText.addValidator(Validators.INTEGERS);
        IntDigitsOnlyFilter intDigitsOnlyFilter = new IntDigitsOnlyFilter(true);
        this.textFieldFilter = intDigitsOnlyFilter;
        valueText.setTextFieldFilter(intDigitsOnlyFilter);
        this.textFieldFilter.setUseFieldCursorPosition(true);
        if (this.min >= 0) {
            this.textFieldFilter.setAcceptNegativeValues(false);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(true);
        }
        spinner.notifyValueChanged(true);
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void textChanged() {
        String text = this.spinner.getTextField().getText();
        if (text.equals(BuildConfig.FLAVOR)) {
            this.current = this.min;
        } else if (checkInputBounds(text)) {
            this.current = Integer.parseInt(text);
        }
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean incrementModel() {
        int i = this.current;
        int i2 = this.step;
        int i3 = i + i2;
        int i4 = this.max;
        if (i3 > i4) {
            if (i == i4) {
                if (isWrap()) {
                    this.current = this.min;
                    return true;
                }
                return false;
            }
            this.current = i4;
        } else {
            this.current = i + i2;
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean decrementModel() {
        int i = this.current;
        int i2 = this.step;
        int i3 = i - i2;
        int i4 = this.min;
        if (i3 < i4) {
            if (i == i4) {
                if (isWrap()) {
                    this.current = this.max;
                    return true;
                }
                return false;
            }
            this.current = i4;
        } else {
            this.current = i - i2;
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public String getText() {
        return String.valueOf(this.current);
    }

    public void setValue(int newValue) {
        setValue(newValue, this.spinner.isProgrammaticChangeEvents());
    }

    public void setValue(int newValue, boolean fireEvent) {
        int i = this.max;
        if (newValue > i) {
            this.current = i;
        } else {
            int i2 = this.min;
            if (newValue < i2) {
                this.current = i2;
            } else {
                this.current = newValue;
            }
        }
        this.spinner.notifyValueChanged(fireEvent);
    }

    public int getValue() {
        return this.current;
    }

    public int getMin() {
        return this.min;
    }

    public void setMin(int min) {
        if (min > this.max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.min = min;
        if (min >= 0) {
            this.textFieldFilter.setAcceptNegativeValues(false);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(true);
        }
        if (this.current < min) {
            this.current = min;
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public int getMax() {
        return this.max;
    }

    public void setMax(int max) {
        if (this.min > max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.max = max;
        if (this.current > max) {
            this.current = max;
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public int getStep() {
        return this.step;
    }

    public void setStep(int step) {
        if (step <= 0) {
            throw new IllegalArgumentException("step must be > 0");
        }
        this.step = step;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkInputBounds(String input) {
        try {
            float x = Integer.parseInt(input);
            if (x >= this.min) {
                return x <= ((float) this.max);
            }
            return false;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /* loaded from: classes.dex */
    private class BoundsValidator implements InputValidator {
        private BoundsValidator() {
        }

        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            return IntSpinnerModel.this.checkInputBounds(input);
        }
    }
}