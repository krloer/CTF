package com.kotcrab.vis.ui.widget.spinner;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.ui.Cell;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.FocusListener;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.Timer;
import com.kotcrab.vis.ui.Sizes;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.VisImageButton;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.VisValidatableTextField;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Spinner extends VisTable {
    private ButtonRepeatTask buttonRepeatTask;
    private boolean disabled;
    private VisImageButton downButton;
    private Cell<VisLabel> labelCell;
    private SpinnerModel model;
    private boolean programmaticChangeEvents;
    private final Sizes sizes;
    private Cell<VisValidatableTextField> textFieldCell;
    private TextFieldEventPolicy textFieldEventPolicy;
    private VisImageButton upButton;

    /* loaded from: classes.dex */
    public enum TextFieldEventPolicy {
        ON_ENTER_ONLY,
        ON_FOCUS_LOST,
        ON_KEY_TYPED
    }

    public Spinner(String name, SpinnerModel model) {
        this("default", name, model);
    }

    public Spinner(String styleName, String name, SpinnerModel model) {
        this((SpinnerStyle) VisUI.getSkin().get(styleName, SpinnerStyle.class), VisUI.getSizes(), name, model);
    }

    public Spinner(SpinnerStyle style, Sizes sizes, String name, SpinnerModel model) {
        this.buttonRepeatTask = new ButtonRepeatTask();
        this.textFieldEventPolicy = TextFieldEventPolicy.ON_FOCUS_LOST;
        this.programmaticChangeEvents = true;
        this.sizes = sizes;
        this.model = model;
        VisTable buttonsTable = new VisTable();
        VisValidatableTextField textField = createTextField();
        this.upButton = new VisImageButton(style.up);
        this.downButton = new VisImageButton(style.down);
        buttonsTable.add((VisTable) this.upButton).height(sizes.spinnerButtonHeight).row();
        buttonsTable.add((VisTable) this.downButton).height(sizes.spinnerButtonHeight);
        this.labelCell = add((Spinner) new VisLabel(BuildConfig.FLAVOR));
        setSelectorName(name);
        this.textFieldCell = add((Spinner) textField).height(sizes.spinnerButtonHeight * 2.0f).growX();
        add((Spinner) buttonsTable);
        addButtonsListeners(this.upButton, this.downButton);
        model.bind(this);
    }

    private VisValidatableTextField createTextField() {
        VisValidatableTextField textField = new VisValidatableTextField() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.1
            @Override // com.kotcrab.vis.ui.widget.VisTextField, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
            public float getPrefWidth() {
                return Spinner.this.sizes.spinnerFieldSize;
            }
        };
        textField.setRestoreLastValid(true);
        textField.setProgrammaticChangeEvents(false);
        addTextFieldListeners(textField);
        return textField;
    }

    public void setModel(SpinnerModel model) {
        this.model = model;
        this.textFieldCell.setActor(createTextField());
        model.bind(this);
    }

    private void addButtonsListeners(VisImageButton upButton, VisImageButton downButton) {
        upButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                event.stop();
                Spinner.this.getStage().setScrollFocus(Spinner.this.getTextField());
                Spinner.this.increment(true);
            }
        });
        downButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                event.stop();
                Spinner.this.getStage().setScrollFocus(Spinner.this.getTextField());
                Spinner.this.decrement(true);
            }
        });
        upButton.addListener(new ButtonInputListener(true));
        downButton.addListener(new ButtonInputListener(false));
    }

    private void addTextFieldListeners(final VisTextField textField) {
        textField.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.4
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                event.stop();
                Spinner.this.model.textChanged();
                if (textField.isInputValid() && Spinner.this.textFieldEventPolicy == TextFieldEventPolicy.ON_KEY_TYPED) {
                    Spinner.this.notifyValueChanged(true);
                }
            }
        });
        textField.addListener(new FocusListener() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.5
            @Override // com.badlogic.gdx.scenes.scene2d.utils.FocusListener
            public void keyboardFocusChanged(FocusListener.FocusEvent event, Actor actor, boolean focused) {
                if (!focused) {
                    Spinner.this.getStage().setScrollFocus(null);
                    if (Spinner.this.textFieldEventPolicy == TextFieldEventPolicy.ON_FOCUS_LOST) {
                        Spinner.this.notifyValueChanged(true);
                    }
                }
            }
        });
        textField.addListener(new InputListener() { // from class: com.kotcrab.vis.ui.widget.spinner.Spinner.6
            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                Spinner.this.getStage().setScrollFocus(Spinner.this.getTextField());
                return true;
            }

            public boolean scrolled(InputEvent event, float x, float y, int amount) {
                if (Spinner.this.disabled) {
                    return false;
                }
                if (amount == 1) {
                    Spinner.this.decrement(true);
                } else {
                    Spinner.this.increment(true);
                }
                return true;
            }

            @Override // com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean keyDown(InputEvent event, int keycode) {
                if (keycode == 66) {
                    Spinner.this.notifyValueChanged(true);
                    return true;
                }
                return false;
            }
        });
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
        this.upButton.setDisabled(disabled);
        this.downButton.setDisabled(disabled);
        getTextField().setDisabled(disabled);
    }

    public boolean isDisabled() {
        return this.disabled;
    }

    public void setSelectorName(String name) {
        this.labelCell.getActor().setText(name);
        if (name == null || name.length() == 0) {
            this.labelCell.padRight(0.0f);
        } else {
            this.labelCell.padRight(6.0f);
        }
    }

    public String getSelectorName() {
        return super.getName();
    }

    public void increment() {
        this.model.increment(this.programmaticChangeEvents);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void increment(boolean fireEvent) {
        this.model.increment(fireEvent);
    }

    public void decrement() {
        this.model.decrement(this.programmaticChangeEvents);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void decrement(boolean fireEvent) {
        this.model.decrement(fireEvent);
    }

    public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
        this.programmaticChangeEvents = programmaticChangeEvents;
    }

    public boolean isProgrammaticChangeEvents() {
        return this.programmaticChangeEvents;
    }

    public void setTextFieldEventPolicy(TextFieldEventPolicy textFieldEventPolicy) {
        this.textFieldEventPolicy = textFieldEventPolicy;
    }

    public TextFieldEventPolicy getTextFieldEventPolicy() {
        return this.textFieldEventPolicy;
    }

    public int getMaxLength() {
        return getTextField().getMaxLength();
    }

    public void setMaxLength(int maxLength) {
        getTextField().setMaxLength(maxLength);
    }

    public SpinnerModel getModel() {
        return this.model;
    }

    public void notifyValueChanged(boolean fireEvent) {
        VisValidatableTextField textField = getTextField();
        int cursor = textField.getCursorPosition();
        textField.setCursorPosition(0);
        textField.setText(this.model.getText());
        textField.setCursorPosition(cursor);
        if (fireEvent) {
            ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
            fire(changeEvent);
            Pools.free(changeEvent);
        }
    }

    public VisValidatableTextField getTextField() {
        return this.textFieldCell.getActor();
    }

    /* loaded from: classes.dex */
    public static class SpinnerStyle {
        public Drawable down;
        public Drawable up;

        public SpinnerStyle() {
        }

        public SpinnerStyle(SpinnerStyle style) {
            this.up = style.up;
            this.down = style.down;
        }

        public SpinnerStyle(Drawable up, Drawable down) {
            this.up = up;
            this.down = down;
        }
    }

    /* loaded from: classes.dex */
    private class ButtonRepeatTask extends Timer.Task {
        boolean advance;

        private ButtonRepeatTask() {
        }

        @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
        public void run() {
            if (this.advance) {
                Spinner.this.increment(true);
            } else {
                Spinner.this.decrement(true);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ButtonInputListener extends InputListener {
        private boolean advance;
        private float buttonRepeatInitialTime = 0.4f;
        private float buttonRepeatTime = 0.08f;

        public ButtonInputListener(boolean advance) {
            this.advance = advance;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
            if (!Spinner.this.buttonRepeatTask.isScheduled()) {
                Spinner.this.buttonRepeatTask.advance = this.advance;
                Spinner.this.buttonRepeatTask.cancel();
                Timer.schedule(Spinner.this.buttonRepeatTask, this.buttonRepeatInitialTime, this.buttonRepeatTime);
                return true;
            }
            return true;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
            Spinner.this.buttonRepeatTask.cancel();
        }
    }
}