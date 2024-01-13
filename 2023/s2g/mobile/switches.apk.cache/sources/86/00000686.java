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
public class FloatSpinnerModel extends AbstractSpinnerModel {
    private InputValidator boundsValidator;
    private BigDecimal current;
    private BigDecimal max;
    private BigDecimal min;
    private int scale;
    private BigDecimal step;
    private NumberDigitsTextFieldFilter textFieldFilter;

    public FloatSpinnerModel(String initialValue, String min, String max) {
        this(initialValue, min, max, "1", 1);
    }

    public FloatSpinnerModel(String initialValue, String min, String max, String step) {
        this(initialValue, min, max, step, 1);
    }

    public FloatSpinnerModel(String initialValue, String min, String max, String step, int scale) {
        this(new BigDecimal(initialValue), new BigDecimal(min), new BigDecimal(max), new BigDecimal(step), scale);
    }

    public FloatSpinnerModel(BigDecimal initialValue, BigDecimal min, BigDecimal max, BigDecimal step, int scale) {
        super(false);
        this.boundsValidator = new BoundsValidator();
        this.scale = 0;
        this.current = initialValue;
        this.max = max;
        this.min = min;
        this.step = step;
        this.scale = scale;
        if (this.min.compareTo(this.max) > 0) {
            throw new IllegalArgumentException("min can't be > max");
        }
        if (this.step.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("step must be > 0");
        }
        if (scale < 0) {
            throw new IllegalArgumentException("scale must be >= 0");
        }
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel, com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void bind(Spinner spinner) {
        super.bind(spinner);
        setScale(this.scale, false);
        spinner.notifyValueChanged(true);
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void textChanged() {
        String text = this.spinner.getTextField().getText();
        if (text.equals(BuildConfig.FLAVOR)) {
            this.current = this.min.setScale(this.scale, 4);
        } else if (checkInputBounds(text)) {
            this.current = new BigDecimal(text);
        }
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean incrementModel() {
        if (this.current.add(this.step).compareTo(this.max) > 0) {
            if (this.current.compareTo(this.max) == 0) {
                if (isWrap()) {
                    this.current = this.min.setScale(this.scale, 4);
                    return true;
                }
                return false;
            }
            this.current = this.max.setScale(this.scale, 4);
        } else {
            this.current = this.current.add(this.step);
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean decrementModel() {
        if (this.current.subtract(this.step).compareTo(this.min) < 0) {
            if (this.current.compareTo(this.min) == 0) {
                if (isWrap()) {
                    this.current = this.max.setScale(this.scale, 4);
                    return true;
                }
                return false;
            }
            this.current = this.min.setScale(this.scale, 4);
        } else {
            this.current = this.current.subtract(this.step);
        }
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public String getText() {
        return this.current.toPlainString();
    }

    public int getScale() {
        return this.scale;
    }

    public void setScale(int scale) {
        setScale(scale, true);
    }

    private void setScale(final int scale, boolean notifySpinner) {
        if (scale < 0) {
            throw new IllegalStateException("Scale can't be < 0");
        }
        this.scale = scale;
        this.current = this.current.setScale(scale, 4);
        VisValidatableTextField valueText = this.spinner.getTextField();
        valueText.getValidators().clear();
        valueText.addValidator(this.boundsValidator);
        if (scale == 0) {
            valueText.addValidator(Validators.INTEGERS);
            IntDigitsOnlyFilter intDigitsOnlyFilter = new IntDigitsOnlyFilter(true);
            this.textFieldFilter = intDigitsOnlyFilter;
            valueText.setTextFieldFilter(intDigitsOnlyFilter);
        } else {
            valueText.addValidator(Validators.FLOATS);
            valueText.addValidator(new InputValidator() { // from class: com.kotcrab.vis.ui.widget.spinner.FloatSpinnerModel.1
                @Override // com.kotcrab.vis.ui.util.InputValidator
                public boolean validateInput(String input) {
                    int dotIndex = input.indexOf(46);
                    return dotIndex == -1 || (input.length() - input.indexOf(46)) - 1 <= scale;
                }
            });
            FloatDigitsOnlyFilter floatDigitsOnlyFilter = new FloatDigitsOnlyFilter(true);
            this.textFieldFilter = floatDigitsOnlyFilter;
            valueText.setTextFieldFilter(floatDigitsOnlyFilter);
        }
        this.textFieldFilter.setUseFieldCursorPosition(true);
        if (this.min.compareTo(BigDecimal.ZERO) < 0) {
            this.textFieldFilter.setAcceptNegativeValues(true);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(false);
        }
        if (notifySpinner) {
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public void setValue(BigDecimal newValue) {
        setValue(newValue, this.spinner.isProgrammaticChangeEvents());
    }

    public void setValue(BigDecimal newValue, boolean fireEvent) {
        if (newValue.compareTo(this.max) > 0) {
            this.current = this.max.setScale(this.scale, 4);
        } else if (newValue.compareTo(this.min) < 0) {
            this.current = this.min.setScale(this.scale, 4);
        } else {
            this.current = newValue.setScale(this.scale, 4);
        }
        this.spinner.notifyValueChanged(fireEvent);
    }

    public BigDecimal getValue() {
        return this.current;
    }

    public BigDecimal getMin() {
        return this.min;
    }

    public void setMin(BigDecimal min) {
        if (min.compareTo(this.max) > 0) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.min = min;
        if (min.compareTo(BigDecimal.ZERO) >= 0) {
            this.textFieldFilter.setAcceptNegativeValues(false);
        } else {
            this.textFieldFilter.setAcceptNegativeValues(true);
        }
        if (this.current.compareTo(min) < 0) {
            this.current = min.setScale(this.scale, 4);
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public BigDecimal getMax() {
        return this.max;
    }

    public void setMax(BigDecimal max) {
        if (this.min.compareTo(max) > 0) {
            throw new IllegalArgumentException("min can't be > max");
        }
        this.max = max;
        if (this.current.compareTo(max) > 0) {
            this.current = max.setScale(this.scale, 4);
            this.spinner.notifyValueChanged(this.spinner.isProgrammaticChangeEvents());
        }
    }

    public BigDecimal getStep() {
        return this.step;
    }

    public void setStep(BigDecimal step) {
        if (step.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("step must be > 0");
        }
        this.step = step;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkInputBounds(String input) {
        try {
            BigDecimal x = new BigDecimal(input);
            if (x.compareTo(this.min) >= 0) {
                return x.compareTo(this.max) <= 0;
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
            return FloatSpinnerModel.this.checkInputBounds(input);
        }
    }
}