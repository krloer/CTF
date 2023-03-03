package com.kotcrab.vis.ui.widget.toast;

import com.badlogic.gdx.math.Interpolation;
import com.badlogic.gdx.scenes.scene2d.Action;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.ToastManager;
import com.kotcrab.vis.ui.widget.VisImageButton;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.VisWindow;

/* loaded from: classes.dex */
public class Toast {
    private Table contentTable;
    private Table mainTable;
    private ToastStyle style;
    private ToastManager toastManager;

    public Toast(Table content) {
        this("default", content);
    }

    public Toast(String styleName, Table content) {
        this((ToastStyle) VisUI.getSkin().get(styleName, ToastStyle.class), content);
    }

    public Toast(ToastStyle style, Table content) {
        this.style = style;
        this.contentTable = content;
        if (content instanceof ToastTable) {
            ((ToastTable) content).setToast(this);
        }
        createMainTable();
    }

    protected void createMainTable() {
        this.mainTable = new VisTable();
        this.mainTable.setBackground(this.style.background);
        VisImageButton closeButton = new VisImageButton(this.style.closeButtonStyle);
        closeButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.toast.Toast.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                Toast.this.close();
            }
        });
        this.mainTable.add(this.contentTable).pad(3.0f).fill().expand();
        this.mainTable.add(closeButton).top();
    }

    protected void close() {
        fadeOut();
    }

    public void fadeOut() {
        this.mainTable.addAction(Actions.sequence(Actions.fadeOut(VisWindow.FADE_TIME, Interpolation.fade), new Action() { // from class: com.kotcrab.vis.ui.widget.toast.Toast.2
            @Override // com.badlogic.gdx.scenes.scene2d.Action
            public boolean act(float delta) {
                Toast.this.toastManager.remove(Toast.this);
                return true;
            }
        }));
    }

    public Table fadeIn() {
        this.mainTable.setColor(1.0f, 1.0f, 1.0f, 0.0f);
        this.mainTable.addAction(Actions.fadeIn(VisWindow.FADE_TIME, Interpolation.fade));
        return this.mainTable;
    }

    public Table getContentTable() {
        return this.contentTable;
    }

    public Table getMainTable() {
        return this.mainTable;
    }

    public void setToastManager(ToastManager toastManager) {
        this.toastManager = toastManager;
    }

    public ToastManager getToastManager() {
        return this.toastManager;
    }

    /* loaded from: classes.dex */
    public static class ToastStyle {
        public Drawable background;
        public VisImageButton.VisImageButtonStyle closeButtonStyle;

        public ToastStyle() {
        }

        public ToastStyle(ToastStyle style) {
            this.background = style.background;
            this.closeButtonStyle = style.closeButtonStyle;
        }

        public ToastStyle(Drawable background, VisImageButton.VisImageButtonStyle closeButtonStyle) {
            this.background = background;
            this.closeButtonStyle = closeButtonStyle;
        }
    }
}