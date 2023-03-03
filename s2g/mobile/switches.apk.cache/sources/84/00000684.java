package com.kotcrab.vis.ui.widget.spinner;

import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.util.InputValidator;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ArraySpinnerModel<T> extends AbstractSpinnerModel {
    private T current;
    private int currentIndex;
    private Array<T> items;

    public ArraySpinnerModel() {
        super(false);
        this.items = new Array<>();
    }

    public ArraySpinnerModel(Array<T> items) {
        super(false);
        this.items = new Array<>();
        this.items.addAll(items);
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel, com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void bind(Spinner spinner) {
        super.bind(spinner);
        updateCurrentItem(0);
        spinner.getTextField().addValidator(new InputValidator() { // from class: com.kotcrab.vis.ui.widget.spinner.ArraySpinnerModel.1
            @Override // com.kotcrab.vis.ui.util.InputValidator
            public boolean validateInput(String input) {
                return ArraySpinnerModel.this.getItemIndexForText(input) != -1;
            }
        });
        spinner.notifyValueChanged(true);
    }

    protected String itemToString(T item) {
        return item == null ? BuildConfig.FLAVOR : item.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getItemIndexForText(String text) {
        for (int i = 0; i < this.items.size; i++) {
            T item = this.items.get(i);
            if (itemToString(item).equals(text)) {
                return i;
            }
        }
        return -1;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public void textChanged() {
        String text = this.spinner.getTextField().getText();
        int index = getItemIndexForText(text);
        if (index == -1) {
            return;
        }
        updateCurrentItem(index);
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean incrementModel() {
        if (this.currentIndex + 1 >= this.items.size) {
            if (isWrap()) {
                updateCurrentItem(0);
                return true;
            }
            return false;
        }
        updateCurrentItem(this.currentIndex + 1);
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.AbstractSpinnerModel
    public boolean decrementModel() {
        int i = this.currentIndex;
        if (i - 1 < 0) {
            if (isWrap()) {
                updateCurrentItem(this.items.size - 1);
                return true;
            }
            return false;
        }
        updateCurrentItem(i - 1);
        return true;
    }

    @Override // com.kotcrab.vis.ui.widget.spinner.SpinnerModel
    public String getText() {
        return itemToString(this.current);
    }

    public void invalidateDataSet() {
        updateCurrentItem(MathUtils.clamp(this.currentIndex, 0, this.items.size - 1));
        this.spinner.notifyValueChanged(true);
    }

    public Array<T> getItems() {
        return this.items;
    }

    public void setItems(Array<T> newItems) {
        this.items.clear();
        this.items.addAll(newItems);
        this.currentIndex = 0;
        invalidateDataSet();
    }

    public int getCurrentIndex() {
        return this.currentIndex;
    }

    public T getCurrent() {
        return this.current;
    }

    public void setCurrent(int newIndex) {
        setCurrent(newIndex, this.spinner.isProgrammaticChangeEvents());
    }

    public void setCurrent(int newIndex, boolean fireEvent) {
        updateCurrentItem(newIndex);
        this.spinner.notifyValueChanged(fireEvent);
    }

    public void setCurrent(T item) {
        setCurrent((ArraySpinnerModel<T>) item, this.spinner.isProgrammaticChangeEvents());
    }

    public void setCurrent(T item, boolean fireEvent) {
        int index = this.items.indexOf(item, true);
        if (index == -1) {
            setCurrent(0, fireEvent);
        } else {
            setCurrent(index, fireEvent);
        }
    }

    private void updateCurrentItem(int newIndex) {
        if (this.items.size == 0) {
            this.current = null;
            this.currentIndex = -1;
            return;
        }
        this.currentIndex = newIndex;
        this.current = this.items.get(newIndex);
    }
}