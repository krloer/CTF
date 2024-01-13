package com.kotcrab.vis.ui.util.form;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.ui.Label;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.kotcrab.vis.ui.util.form.SimpleFormValidator;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import java.io.File;

/* loaded from: classes.dex */
public class FormValidator extends SimpleFormValidator {
    public FormValidator(Disableable targetToDisable) {
        super(targetToDisable);
    }

    public FormValidator(Disableable targetToDisable, Label messageLabel) {
        super(targetToDisable, messageLabel);
    }

    public FormValidator(Disableable targetToDisable, Label messageLabel, String styleName) {
        super(targetToDisable, messageLabel, styleName);
    }

    public FormValidator(Disableable targetToDisable, Label messageLabel, SimpleFormValidator.FormValidatorStyle style) {
        super(targetToDisable, messageLabel, style);
    }

    public FormInputValidator fileExists(VisValidatableTextField field, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileExists(VisValidatableTextField field, VisTextField relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo, errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileExists(VisValidatableTextField field, VisTextField relativeTo, String errorMsg, boolean errorIfRelativeEmpty) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo, errorMsg, false, errorIfRelativeEmpty);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileExists(VisValidatableTextField field, File relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo, errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileExists(VisValidatableTextField field, FileHandle relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo.file(), errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileNotExists(VisValidatableTextField field, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(errorMsg, true);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileNotExists(VisValidatableTextField field, VisTextField relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo, errorMsg, true);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileNotExists(VisValidatableTextField field, File relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo, errorMsg, true);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator fileNotExists(VisValidatableTextField field, FileHandle relativeTo, String errorMsg) {
        FileExistsValidator validator = new FileExistsValidator(relativeTo.file(), errorMsg, true);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator directory(VisValidatableTextField field, String errorMsg) {
        DirectoryValidator validator = new DirectoryValidator(errorMsg);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator directoryEmpty(VisValidatableTextField field, String errorMsg) {
        DirectoryContentValidator validator = new DirectoryContentValidator(errorMsg, true);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    public FormInputValidator directoryNotEmpty(VisValidatableTextField field, String errorMsg) {
        DirectoryContentValidator validator = new DirectoryContentValidator(errorMsg, false);
        field.addValidator(validator);
        add(field);
        return validator;
    }

    /* loaded from: classes.dex */
    public static class DirectoryValidator extends FormInputValidator {
        public DirectoryValidator(String errorMsg) {
            super(errorMsg);
        }

        @Override // com.kotcrab.vis.ui.util.form.FormInputValidator
        protected boolean validate(String input) {
            FileHandle file = Gdx.files.absolute(input);
            return file.exists() && file.isDirectory();
        }
    }

    /* loaded from: classes.dex */
    public static class DirectoryContentValidator extends FormInputValidator {
        private boolean mustBeEmpty;

        public DirectoryContentValidator(String errorMsg, boolean mustBeEmpty) {
            super(errorMsg);
            this.mustBeEmpty = mustBeEmpty;
        }

        @Override // com.kotcrab.vis.ui.util.form.FormInputValidator
        protected boolean validate(String input) {
            FileHandle file = Gdx.files.absolute(input);
            if (file.exists() && file.isDirectory()) {
                return this.mustBeEmpty ? file.list().length == 0 : file.list().length != 0;
            }
            return false;
        }

        public void setMustBeEmpty(boolean mustBeEmpty) {
            this.mustBeEmpty = mustBeEmpty;
        }

        public boolean isMustBeEmpty() {
            return this.mustBeEmpty;
        }
    }

    /* loaded from: classes.dex */
    public static class FileExistsValidator extends FormInputValidator {
        boolean errorIfRelativeEmpty;
        boolean mustNotExist;
        VisTextField relativeTo;
        File relativeToFile;

        public FileExistsValidator(String errorMsg) {
            this(errorMsg, false);
        }

        public FileExistsValidator(String errorMsg, boolean mustNotExist) {
            super(errorMsg);
            this.mustNotExist = mustNotExist;
        }

        public FileExistsValidator(File relativeTo, String errorMsg) {
            this(relativeTo, errorMsg, false);
        }

        public FileExistsValidator(File relativeTo, String errorMsg, boolean mustNotExist) {
            super(errorMsg);
            this.relativeToFile = relativeTo;
            this.mustNotExist = mustNotExist;
        }

        public FileExistsValidator(VisTextField relativeTo, String errorMsg) {
            this(relativeTo, errorMsg, false);
        }

        public FileExistsValidator(VisTextField relativeTo, String errorMsg, boolean mustNotExist) {
            super(errorMsg);
            this.relativeTo = relativeTo;
            this.mustNotExist = mustNotExist;
        }

        public FileExistsValidator(VisTextField relativeTo, String errorMsg, boolean mustNotExist, boolean errorIfRelativeEmpty) {
            super(errorMsg);
            this.relativeTo = relativeTo;
            this.mustNotExist = mustNotExist;
            this.errorIfRelativeEmpty = errorIfRelativeEmpty;
        }

        @Override // com.kotcrab.vis.ui.util.form.FormInputValidator
        public boolean validate(String input) {
            File file;
            VisTextField visTextField = this.relativeTo;
            if (visTextField != null) {
                if (visTextField.getText().length() == 0 && !this.errorIfRelativeEmpty) {
                    return true;
                }
                file = new File(this.relativeTo.getText(), input);
            } else {
                File file2 = this.relativeToFile;
                if (file2 != null) {
                    file = new File(file2, input);
                } else {
                    file = new File(input);
                }
            }
            if (this.mustNotExist) {
                return true ^ file.exists();
            }
            return file.exists();
        }

        public void setRelativeToFile(File relativeToFile) {
            if (this.relativeTo != null) {
                throw new IllegalStateException("This validator already has relativeToTextField set");
            }
            this.relativeToFile = relativeToFile;
        }

        public void setRelativeToTextField(VisTextField relativeTo) {
            if (this.relativeToFile != null) {
                throw new IllegalStateException("This validator already has relativeToFile set.");
            }
            this.relativeTo = relativeTo;
        }

        public void setMustNotExist(boolean notExist) {
            this.mustNotExist = notExist;
        }

        public void setErrorIfRelativeEmpty(boolean errorIfRelativeEmpty) {
            this.errorIfRelativeEmpty = errorIfRelativeEmpty;
        }
    }
}