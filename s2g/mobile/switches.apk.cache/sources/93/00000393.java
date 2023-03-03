package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.scenes.scene2d.ui.Button;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public class ButtonGroup<T extends Button> {
    private final Array<T> buttons;
    private Array<T> checkedButtons;
    private T lastChecked;
    private int maxCheckCount;
    private int minCheckCount;
    private boolean uncheckLast;

    public ButtonGroup() {
        this.buttons = new Array<>();
        this.checkedButtons = new Array<>(1);
        this.maxCheckCount = 1;
        this.uncheckLast = true;
        this.minCheckCount = 1;
    }

    public ButtonGroup(T... buttons) {
        this.buttons = new Array<>();
        this.checkedButtons = new Array<>(1);
        this.maxCheckCount = 1;
        this.uncheckLast = true;
        this.minCheckCount = 0;
        add(buttons);
        this.minCheckCount = 1;
    }

    public void add(T button) {
        if (button == null) {
            throw new IllegalArgumentException("button cannot be null.");
        }
        button.buttonGroup = null;
        boolean shouldCheck = button.isChecked() || this.buttons.size < this.minCheckCount;
        button.setChecked(false);
        button.buttonGroup = this;
        this.buttons.add(button);
        button.setChecked(shouldCheck);
    }

    public void add(T... buttons) {
        if (buttons == null) {
            throw new IllegalArgumentException("buttons cannot be null.");
        }
        for (T t : buttons) {
            add((ButtonGroup<T>) t);
        }
    }

    public void remove(T button) {
        if (button == null) {
            throw new IllegalArgumentException("button cannot be null.");
        }
        button.buttonGroup = null;
        this.buttons.removeValue(button, true);
        this.checkedButtons.removeValue(button, true);
    }

    public void remove(T... buttons) {
        if (buttons == null) {
            throw new IllegalArgumentException("buttons cannot be null.");
        }
        for (T t : buttons) {
            remove((ButtonGroup<T>) t);
        }
    }

    public void clear() {
        this.buttons.clear();
        this.checkedButtons.clear();
    }

    public void setChecked(String text) {
        if (text == null) {
            throw new IllegalArgumentException("text cannot be null.");
        }
        int n = this.buttons.size;
        for (int i = 0; i < n; i++) {
            T button = this.buttons.get(i);
            if ((button instanceof TextButton) && text.contentEquals(((TextButton) button).getText())) {
                button.setChecked(true);
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean canCheck(T button, boolean newState) {
        if (button.isChecked == newState) {
            return false;
        }
        if (!newState) {
            if (this.checkedButtons.size <= this.minCheckCount) {
                return false;
            }
            this.checkedButtons.removeValue(button, true);
        } else {
            if (this.maxCheckCount != -1 && this.checkedButtons.size >= this.maxCheckCount) {
                if (!this.uncheckLast) {
                    return false;
                }
                int tries = 0;
                while (true) {
                    int old = this.minCheckCount;
                    this.minCheckCount = 0;
                    this.lastChecked.setChecked(false);
                    this.minCheckCount = old;
                    if (button.isChecked == newState) {
                        return false;
                    }
                    if (this.checkedButtons.size < this.maxCheckCount) {
                        break;
                    }
                    int tries2 = tries + 1;
                    if (tries > 10) {
                        return false;
                    }
                    tries = tries2;
                }
            }
            this.checkedButtons.add(button);
            this.lastChecked = button;
        }
        return true;
    }

    public void uncheckAll() {
        int old = this.minCheckCount;
        this.minCheckCount = 0;
        int n = this.buttons.size;
        for (int i = 0; i < n; i++) {
            T button = this.buttons.get(i);
            button.setChecked(false);
        }
        this.minCheckCount = old;
    }

    public T getChecked() {
        if (this.checkedButtons.size > 0) {
            return this.checkedButtons.get(0);
        }
        return null;
    }

    public int getCheckedIndex() {
        if (this.checkedButtons.size > 0) {
            return this.buttons.indexOf(this.checkedButtons.get(0), true);
        }
        return -1;
    }

    public Array<T> getAllChecked() {
        return this.checkedButtons;
    }

    public Array<T> getButtons() {
        return this.buttons;
    }

    public void setMinCheckCount(int minCheckCount) {
        this.minCheckCount = minCheckCount;
    }

    public void setMaxCheckCount(int maxCheckCount) {
        if (maxCheckCount == 0) {
            maxCheckCount = -1;
        }
        this.maxCheckCount = maxCheckCount;
    }

    public void setUncheckLast(boolean uncheckLast) {
        this.uncheckLast = uncheckLast;
    }
}