package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Disposable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.widget.ButtonBar;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisTextButton;
import com.kotcrab.vis.ui.widget.VisWindow;
import com.kotcrab.vis.ui.widget.color.internal.ColorPickerText;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class ColorPicker extends VisWindow implements Disposable {
    private VisTextButton cancelButton;
    private boolean closeAfterPickingFinished;
    private boolean fadeOutDueToCanceled;
    private ColorPickerListener listener;
    private VisTextButton okButton;
    private ExtendedColorPicker picker;
    private VisTextButton restoreButton;

    public ColorPicker() {
        this((String) null);
    }

    public ColorPicker(String title) {
        this("default", title, null);
    }

    public ColorPicker(String title, ColorPickerListener listener) {
        this("default", title, listener);
    }

    public ColorPicker(ColorPickerListener listener) {
        this("default", null, listener);
    }

    public ColorPicker(String styleName, String title, ColorPickerListener listener) {
        super(title != null ? title : BuildConfig.FLAVOR, (Window.WindowStyle) VisUI.getSkin().get(styleName, ColorPickerStyle.class));
        this.closeAfterPickingFinished = true;
        this.listener = listener;
        ColorPickerStyle style = (ColorPickerStyle) getStyle();
        if (title == null) {
            getTitleLabel().setText(ColorPickerText.TITLE.get());
        }
        setModal(true);
        setMovable(true);
        addCloseButton();
        closeOnEscape();
        this.picker = new ExtendedColorPicker(style.pickerStyle, listener);
        add((ColorPicker) this.picker);
        row();
        add((ColorPicker) createButtons()).pad(3.0f).right().expandX().colspan(3);
        pack();
        centerWindow();
        createListeners();
    }

    private VisTable createButtons() {
        ButtonBar buttonBar = new ButtonBar();
        buttonBar.setIgnoreSpacing(true);
        ButtonBar.ButtonType buttonType = ButtonBar.ButtonType.LEFT;
        VisTextButton visTextButton = new VisTextButton(ColorPickerText.RESTORE.get());
        this.restoreButton = visTextButton;
        buttonBar.setButton(buttonType, visTextButton);
        ButtonBar.ButtonType buttonType2 = ButtonBar.ButtonType.OK;
        VisTextButton visTextButton2 = new VisTextButton(ColorPickerText.OK.get());
        this.okButton = visTextButton2;
        buttonBar.setButton(buttonType2, visTextButton2);
        ButtonBar.ButtonType buttonType3 = ButtonBar.ButtonType.CANCEL;
        VisTextButton visTextButton3 = new VisTextButton(ColorPickerText.CANCEL.get());
        this.cancelButton = visTextButton3;
        buttonBar.setButton(buttonType3, visTextButton3);
        return buttonBar.createTable();
    }

    private void createListeners() {
        this.restoreButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.ColorPicker.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                ColorPicker.this.picker.restoreLastColor();
            }
        });
        this.okButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.ColorPicker.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                if (ColorPicker.this.listener != null) {
                    ColorPicker.this.listener.finished(new Color(ColorPicker.this.picker.color));
                }
                ColorPicker colorPicker = ColorPicker.this;
                colorPicker.setColor(colorPicker.picker.color);
                if (ColorPicker.this.closeAfterPickingFinished) {
                    ColorPicker.this.fadeOut();
                }
            }
        });
        this.cancelButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.color.ColorPicker.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                ColorPicker.this.fadeOutDueToCanceled = true;
                ColorPicker.this.close();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisWindow, com.badlogic.gdx.scenes.scene2d.Group, com.badlogic.gdx.scenes.scene2d.Actor
    public void setStage(Stage stage) {
        super.setStage(stage);
        if (stage == null && this.fadeOutDueToCanceled) {
            this.fadeOutDueToCanceled = false;
            setColor(this.picker.oldColor);
        }
    }

    public void setCloseAfterPickingFinished(boolean closeAfterPickingFinished) {
        this.closeAfterPickingFinished = closeAfterPickingFinished;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisWindow
    public void close() {
        ColorPickerListener colorPickerListener = this.listener;
        if (colorPickerListener != null) {
            colorPickerListener.canceled(this.picker.oldColor);
        }
        super.close();
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        this.picker.dispose();
    }

    public ExtendedColorPicker getPicker() {
        return this.picker;
    }

    public boolean isShowHexFields() {
        return this.picker.isShowHexFields();
    }

    public void setShowHexFields(boolean showHexFields) {
        this.picker.setShowHexFields(showHexFields);
    }

    public boolean isDisposed() {
        return this.picker.isDisposed();
    }

    public void setAllowAlphaEdit(boolean allowAlphaEdit) {
        this.picker.setAllowAlphaEdit(allowAlphaEdit);
    }

    public boolean isAllowAlphaEdit() {
        return this.picker.isAllowAlphaEdit();
    }

    public void restoreLastColor() {
        this.picker.restoreLastColor();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public void setColor(Color newColor) {
        this.picker.setColor(newColor);
    }

    public void setListener(ColorPickerListener listener) {
        this.listener = listener;
        this.picker.setListener(listener);
    }

    public ColorPickerListener getListener() {
        return this.picker.getListener();
    }
}