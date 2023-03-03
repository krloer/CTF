package com.kotcrab.vis.ui.util;

/* loaded from: classes.dex */
public class Validators {
    public static final IntegerValidator INTEGERS = new IntegerValidator();
    public static final FloatValidator FLOATS = new FloatValidator();

    /* loaded from: classes.dex */
    public static class IntegerValidator implements InputValidator {
        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            try {
                Integer.parseInt(input);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class FloatValidator implements InputValidator {
        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            try {
                Float.parseFloat(input);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class LesserThanValidator implements InputValidator {
        private boolean equals;
        private float lesserThan;

        public LesserThanValidator(float lesserThan) {
            this.lesserThan = lesserThan;
        }

        public LesserThanValidator(float lesserThan, boolean inputCanBeEqual) {
            this.lesserThan = lesserThan;
            this.equals = inputCanBeEqual;
        }

        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            try {
                float value = Float.valueOf(input).floatValue();
                if (this.equals) {
                    if (value > this.lesserThan) {
                        return false;
                    }
                } else if (value >= this.lesserThan) {
                    return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        public void setUseEquals(boolean equals) {
            this.equals = equals;
        }

        public void setLesserThan(float lesserThan) {
            this.lesserThan = lesserThan;
        }
    }

    /* loaded from: classes.dex */
    public static class GreaterThanValidator implements InputValidator {
        private float greaterThan;
        private boolean useEquals;

        public GreaterThanValidator(float greaterThan) {
            this.greaterThan = greaterThan;
        }

        public GreaterThanValidator(float greaterThan, boolean inputCanBeEqual) {
            this.greaterThan = greaterThan;
            this.useEquals = inputCanBeEqual;
        }

        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            try {
                float value = Float.valueOf(input).floatValue();
                if (this.useEquals) {
                    if (value < this.greaterThan) {
                        return false;
                    }
                } else if (value <= this.greaterThan) {
                    return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        public void setUseEquals(boolean useEquals) {
            this.useEquals = useEquals;
        }

        public void setGreaterThan(float greaterThan) {
            this.greaterThan = greaterThan;
        }
    }
}