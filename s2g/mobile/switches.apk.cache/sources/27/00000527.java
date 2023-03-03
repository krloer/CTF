package com.kotcrab.vis.ui.util;

import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.Table;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.Timer;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.toast.Toast;
import com.kotcrab.vis.ui.widget.toast.ToastTable;
import java.util.Iterator;

/* loaded from: classes.dex */
public class ToastManager {
    public static final int UNTIL_CLOSED = -1;
    private Stage stage;
    private int screenPadding = 20;
    private int messagePadding = 5;
    private int alignment = 18;
    private Array<Toast> toasts = new Array<>();
    private ObjectMap<Toast, Timer.Task> timersTasks = new ObjectMap<>();

    public ToastManager(Stage stage) {
        this.stage = stage;
    }

    public void show(String text) {
        show(text, -1.0f);
    }

    public void show(String text, float timeSec) {
        VisTable table = new VisTable();
        table.add(text).grow();
        show(table, timeSec);
    }

    public void show(Table table) {
        show(table, -1.0f);
    }

    public void show(Table table, float timeSec) {
        show(new Toast(table), timeSec);
    }

    public void show(ToastTable toastTable) {
        show(toastTable, -1.0f);
    }

    public void show(ToastTable toastTable, float timeSec) {
        Toast toast = toastTable.getToast();
        if (toast != null) {
            show(toast, timeSec);
        } else {
            show(new Toast(toastTable), timeSec);
        }
    }

    public void show(Toast toast) {
        show(toast, -1.0f);
    }

    public void show(final Toast toast, float timeSec) {
        Table toastMainTable = toast.getMainTable();
        if (toastMainTable.getStage() != null) {
            remove(toast);
        }
        this.toasts.add(toast);
        toast.setToastManager(this);
        toast.fadeIn();
        toastMainTable.pack();
        this.stage.addActor(toastMainTable);
        updateToastsPositions();
        if (timeSec > 0.0f) {
            Timer.Task fadeOutTask = new Timer.Task() { // from class: com.kotcrab.vis.ui.util.ToastManager.1
                @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
                public void run() {
                    toast.fadeOut();
                    ToastManager.this.timersTasks.remove(toast);
                }
            };
            this.timersTasks.put(toast, fadeOutTask);
            Timer.schedule(fadeOutTask, timeSec);
        }
    }

    public void resize() {
        updateToastsPositions();
    }

    public boolean remove(Toast toast) {
        boolean removed = this.toasts.removeValue(toast, true);
        if (removed) {
            toast.getMainTable().remove();
            Timer.Task timerTask = this.timersTasks.remove(toast);
            if (timerTask != null) {
                timerTask.cancel();
            }
            updateToastsPositions();
        }
        return removed;
    }

    public void clear() {
        Iterator it = this.toasts.iterator();
        while (it.hasNext()) {
            Toast toast = (Toast) it.next();
            toast.getMainTable().remove();
        }
        this.toasts.clear();
        ObjectMap.Values<Timer.Task> it2 = this.timersTasks.values().iterator();
        while (it2.hasNext()) {
            Timer.Task task = it2.next();
            task.cancel();
        }
        this.timersTasks.clear();
        updateToastsPositions();
    }

    public void toFront() {
        Iterator it = this.toasts.iterator();
        while (it.hasNext()) {
            Toast toast = (Toast) it.next();
            toast.getMainTable().toFront();
        }
    }

    private void updateToastsPositions() {
        boolean bottom = (this.alignment & 4) != 0;
        boolean left = (this.alignment & 8) != 0;
        float y = bottom ? this.screenPadding : this.stage.getHeight() - this.screenPadding;
        Iterator it = this.toasts.iterator();
        while (it.hasNext()) {
            Toast toast = (Toast) it.next();
            Table table = toast.getMainTable();
            table.setPosition(left ? this.screenPadding : (this.stage.getWidth() - table.getWidth()) - this.screenPadding, bottom ? y : y - table.getHeight());
            y += (table.getHeight() + this.messagePadding) * (bottom ? 1 : -1);
        }
    }

    public int getScreenPadding() {
        return this.screenPadding;
    }

    public void setScreenPadding(int screenPadding) {
        this.screenPadding = screenPadding;
        updateToastsPositions();
    }

    public int getMessagePadding() {
        return this.messagePadding;
    }

    public void setMessagePadding(int messagePadding) {
        this.messagePadding = messagePadding;
        updateToastsPositions();
    }

    public int getAlignment() {
        return this.alignment;
    }

    public void setAlignment(int alignment) {
        this.alignment = alignment;
        updateToastsPositions();
    }
}