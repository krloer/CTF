package com.kotcrab.vis.ui.widget.color.internal;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.kotcrab.vis.ui.util.InputValidator;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ColorInputField extends VisValidatableTextField {
    private int maxValue;
    private int value;

    /* loaded from: classes.dex */
    public interface ColorInputFieldListener {
        void changed(int i);
    }

    public ColorInputField(final int maxValue, final ColorInputFieldListener listener) {
        super(new ColorFieldValidator(maxValue));
        this.value = 0;
        this.maxValue = maxValue;
        setProgrammaticChangeEvents(false);
        setMaxLength(3);
        setTextFieldFilter(new NumberFilter());
        addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ColorInputField.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (ColorInputField.this.getText().length() > 0) {
                    ColorInputField colorInputField = ColorInputField.this;
                    colorInputField.value = Integer.valueOf(colorInputField.getText()).intValue();
                }
            }
        });
        addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ColorInputField.2
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyTyped(InputEvent event, char character) {
                ColorInputField field = (ColorInputField) event.getListenerActor();
                if (character == '+') {
                    field.changeValue(UIUtils.shift() ? 10 : 1);
                }
                if (character == '-') {
                    field.changeValue(UIUtils.shift() ? -10 : -1);
                }
                if (character != 0) {
                    listener.changed(ColorInputField.this.getValue());
                }
                return true;
            }
        });
        addListener(new FocusListener() { // from class: com.kotcrab.vis.ui.widget.color.internal.ColorInputField.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
            public void keyboardFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
                if (!focused && !ColorInputField.this.isInputValid()) {
                    ColorInputField.this.setValue(maxValue);
                }
            }
        });
    }

    public void changeValue(int byValue) {
        this.value += byValue;
        int i = this.value;
        int i2 = this.maxValue;
        if (i > i2) {
            this.value = i2;
        }
        if (this.value < 0) {
            this.value = 0;
        }
        updateUI();
    }

    public int getValue() {
        return this.value;
    }

    public void setValue(int value) {
        this.value = value;
        updateUI();
    }

    private void updateUI() {
        setText(String.valueOf(this.value));
        setCursorPosition(getMaxLength());
    }

    /* loaded from: classes.dex */
    private static class NumberFilter implements VisTextField.TextFieldFilter {
        private NumberFilter() {
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldFilter
        public boolean acceptChar(VisTextField textField, char c) {
            return Character.isDigit(c);
        }
    }

    /* loaded from: classes.dex */
    private static class ColorFieldValidator implements InputValidator {
        private int maxValue;

        public ColorFieldValidator(int maxValue) {
            this.maxValue = maxValue;
        }

        @Override // com.kotcrab.vis.ui.util.InputValidator
        public boolean validateInput(String input) {
            if (input.equals(BuildConfig.FLAVOR)) {
                return false;
            }
            Integer number = Integer.valueOf(Integer.parseInt(input));
            return number.intValue() <= this.maxValue;
        }
    }
}