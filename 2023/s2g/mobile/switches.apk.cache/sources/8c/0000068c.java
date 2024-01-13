package com.kotcrab.vis.ui.widget.spinner;

import com.kotcrab.vis.ui.util.FloatDigitsOnlyFilter;
import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.util.IntDigitsOnlyFilter;
import com.kotcrab.vis.ui.util.NumberDigitsTextFieldFilter;
import com.kotcrab.vis.ui.util.Validators;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import java.math.BigDecimal;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class SimpleFloatSpinnerModel extends AbstractSpinnerModel {
    private InputValidator boundsValidator;
    private float current;
    private float max;
    private float min;
    private int precision;
    private float step;
    private NumberDigitsTextFieldFilter textFieldFilter;

    public SimpleFloatSpinnerModel(float initialValue, float min, float max) {
        this(initialValue, min, max, 1.0f, 1);
    }

    public SimpleFloatSpinnerModel(float initialValue, float min, float max, float step) {
        this(initialValue, min, max, step, 1);
    }

    public SimpleFloatSpinnerModel(float initialValue, float min, float max, float step, int precision) {
        super(false);
        this.boundsValidator = new BoundsValidator();
        this.precision = 0;
        if (min > max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        if (step <= 0.0f) {
            throw new IllegalArgumentException("step must be > 0");
        }
        if (precision < 0) {
            throw new IllegalArgumentException("precision must be >= 0");
        }
        this.current = initialValue;
        this.max = max;
        this.min = min;
        this.step = step;
        this.precision = precision;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel, com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void bind(Spinner spinner) {
        super.bind(spinner);
        setPrecision(this.precision, false);
        spinner.notifyValueChanged(true);
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void textChanged() {
        String text = this.spinner.getTextField().getText();
        if (text.equals(BuildConfig.FLAVOR)) {
            this.current = this.min;
        } else if (checkInputBounds(text)) {
            this.current = Float.parseFloat(text);
        }
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean incrementModel() {
        float f = this.current;
        float f2 = this.step;
        float f3 = this.max;
        if (f + f2 > f3) {
            if (f == f3) {
                if (isWrap()) {
                    this.current = this.min;
                    return true;
                }
                return false;
            }
            this.current = f3;
        } else {
            this.current = f + f2;
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean decrementModel() {
        float f = this.current;
        float f2 = this.step;
        float f3 = this.min;
        if (f - f2 < f3) {
            if (f == f3) {
                if (isWrap()) {
                    this.current = this.max;
                    return true;
                }
                return false;
            }
            this.current = f3;
        } else {
            this.current = f - f2;
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public String getText() {
        if (this.precision >= 1) {
            BigDecimal bd = new BigDecimal(String.valueOf(this.current));
            return String.valueOf(bd.setScale(this.precision, 4).floatValue());
        }
        return String.valueOf((int) this.current);
    }

    public int getPrecision() {
        return this.precision;
    }

    public void setPrecision(int precision) {
        setPrecision(precision, true);
    }

    private void setPrecision(final int precision, boolean notifySpinner) {
        if (precision < 0) {
            throw new IllegalStateException("Precision can't be < 0");
        }
        this.precision = precision;
        VisValidatableTextField valueText = this.spinner.getTextField();
        valueText.getValidators().clear();
        valueText.addValidator(this.boundsValidator);
        if (precision == 0) {
            valueText.addValidator(Validators.INTEGERS);
            IntDigitsOnlyFilter intDigitsOnlyFilter = new IntDigitsOnlyFilter(true);
            this.textFieldFilter = intDigitsOnlyFilter;
            valueText.setTextFieldFilter(intDigitsOnlyFilter);
        } else {
            valueText.addValidator(Validators.FLOATS);
            valueText.addValidator(new InputValidator() { // from class: com.kotcrab.vis.ui.widget.spinner.SimpleFloatSpinnerModel.1
                @Override // com.kotcrab.vis.ui.util.InputValidator
                public boolean validateInput(String input) {
                    int dotIndex = input.indexOf(46);
                    return dotIndex == -1 || (input.length() - input.indexOf(46)) - 1 <= precision;
                }
            });
            FloatDigitsOnlyFilter floatDigitsOnlyFilter = new FloatDigitsOnlyFilter(true);
            this.textFieldFilter = floatDigitsOnlyFilter;
            valueText.setTextFieldFilter(floatDigitsOnlyFilter);
        }
        this.textFieldFilter.setUseFieldCursorPosition(true);
        if (this.min < 0.0f) {
            this.textFieldFilter.setAcceptNegativeValues(true);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(false);
        }
        if (notifySpinner) {
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public void setValue(float newValue) {
        setValue(newValue, this.spinner.isProgrammaticChangeEvents());
    }

    public void setValue(float newValue, boolean fireEvent) {
        float f = this.max;
        if (newValue > f) {
            this.current = f;
        } else {
            float f2 = this.min;
            if (newValue < f2) {
                this.current = f2;
            } else {
                this.current = newValue;
            }
        }
        this.spinner.notifyValueChanged(fireEvent);
    }

    public float getValue() {
        return this.current;
    }

    public float getMin() {
        return this.min;
    }

    public void setMin(float min) {
        if (min > this.max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.min = min;
        if (min >= 0.0f) {
            this.textFieldFilter.setAcceptNegativeValues(false);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(true);
        }
        if (this.current < min) {
            this.current = min;
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public float getMax() {
        return this.max;
    }

    public void setMax(float max) {
        if (this.min > max) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.max = max;
        if (this.current > max) {
            this.current = max;
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public float getStep() {
        return this.step;
    }

    public void setStep(float step) {
        if (step <= 0.0f) {
            throw new IllegalArgumentException("step must be > 0");
        }
        this.step = step;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkInputBounds(String input) {
        try {
            float x = Float.parseFloat(input);
            if (x >= this.min) {
                return x <= this.max;
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
            return SimpleFloatSpinnerModel.this.checkInputBounds(input);
        }
    }
}