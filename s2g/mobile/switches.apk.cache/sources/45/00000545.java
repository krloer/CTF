package com.kotcrab.vis.ui.util.async;

import com.kotcrab.vis.ui.Locales;
import com.kotcrab.vis.ui.util.TableUtils;
import com.kotcrab.vis.ui.util.async.AsyncTask;
import com.kotcrab.vis.ui.util.dialog.Dialogs;
import com.kotcrab.vis.ui.widget.VisLabel;
import com.kotcrab.vis.ui.widget.VisProgressBar;
import com.kotcrab.vis.ui.widget.VisWindow;

/* loaded from: classes.dex */
public class AsyncTaskProgressDialog extends VisWindow {
    private AsyncTask task;

    public AsyncTaskProgressDialog(String title, AsyncTask task) {
        super(title);
        this.task = task;
        setModal(true);
        TableUtils.setSpacingDefaults(this);
        final VisLabel statusLabel = new VisLabel(Locales.CommonText.PLEASE_WAIT.get());
        final VisProgressBar progressBar = new VisProgressBar(0.0f, 100.0f, 1.0f, false);
        defaults().padLeft(6.0f).padRight(6.0f);
        add((AsyncTaskProgressDialog) statusLabel).padTop(6.0f).left().row();
        add((AsyncTaskProgressDialog) progressBar).width(300.0f).padTop(6.0f).padBottom(6.0f);
        task.addListener(new AsyncTaskListener() { // from class: com.kotcrab.vis.ui.util.async.AsyncTaskProgressDialog.1
            @Override // com.kotcrab.vis.ui.util.async.AsyncTaskListener
            public void progressChanged(int newProgressPercent) {
                progressBar.setValue(newProgressPercent);
            }

            @Override // com.kotcrab.vis.ui.util.async.AsyncTaskListener
            public void messageChanged(String message) {
                statusLabel.setText(message);
            }

            @Override // com.kotcrab.vis.ui.util.async.AsyncTaskListener
            public void finished() {
                AsyncTaskProgressDialog.this.fadeOut();
            }

            @Override // com.kotcrab.vis.ui.util.async.AsyncTaskListener
            public void failed(String message, Exception exception) {
                Dialogs.showErrorDialog(AsyncTaskProgressDialog.this.getStage(), exception.getMessage() == null ? Locales.CommonText.UNKNOWN_ERROR_OCCURRED.get() : exception.getMessage(), exception);
            }
        });
        pack();
        centerWindow();
        task.execute();
    }

    public AsyncTask getTask() {
        return this.task;
    }

    public void addListener(AsyncTaskListener listener) {
        this.task.addListener(listener);
    }

    public AsyncTask.Status getStatus() {
        return this.task.getStatus();
    }
}