package com.kotcrab.vis.ui.widget.tabbedpane;

import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.utils.Disposable;

/* loaded from: classes.dex */
public abstract class Tab implements Disposable {
    private boolean activeTab;
    private boolean closeableByUser;
    private boolean dirty;
    private TabbedPane pane;
    private boolean savable;

    public abstract Table getContentTable();

    public abstract String getTabTitle();

    public Tab() {
        this.closeableByUser = true;
        this.savable = false;
        this.dirty = false;
    }

    public Tab(boolean savable) {
        this.closeableByUser = true;
        this.savable = false;
        this.dirty = false;
        this.savable = savable;
    }

    public Tab(boolean savable, boolean closeableByUser) {
        this.closeableByUser = true;
        this.savable = false;
        this.dirty = false;
        this.savable = savable;
        this.closeableByUser = closeableByUser;
    }

    public void onShow() {
        this.activeTab = true;
    }

    public void onHide() {
        this.activeTab = false;
    }

    public boolean isActiveTab() {
        return this.activeTab;
    }

    public TabbedPane getPane() {
        return this.pane;
    }

    public void setPane(TabbedPane pane) {
        this.pane = pane;
    }

    public boolean isSavable() {
        return this.savable;
    }

    public boolean isCloseableByUser() {
        return this.closeableByUser;
    }

    public boolean isDirty() {
        return this.dirty;
    }

    public void setDirty(boolean dirty) {
        checkSavable();
        boolean update = dirty != this.dirty;
        if (update) {
            this.dirty = dirty;
            if (this.pane != null) {
                getPane().updateTabTitle(this);
            }
        }
    }

    public void dirty() {
        setDirty(true);
    }

    public boolean save() {
        checkSavable();
        return false;
    }

    private void checkSavable() {
        if (!isSavable()) {
            throw new IllegalStateException("Tab " + getTabTitle() + " is not savable!");
        }
    }

    public void removeFromTabPane() {
        TabbedPane tabbedPane = this.pane;
        if (tabbedPane != null) {
            tabbedPane.remove(this);
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
    }
}