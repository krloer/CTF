package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.util.dialog.Dialogs;
import com.kotcrab.vis.ui.widget.VisImageButton;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.file.FileChooser;
import com.kotcrab.vis.ui.widget.file.FileChooserStyle;

/* loaded from: classes.dex */
public class FileHistoryManager {
    private VisImageButton backButton;
    private VisTable buttonsTable;
    private final FileHistoryCallback callback;
    private VisImageButton forwardButton;
    private Array<FileHandle> history = new Array<>();
    private Array<FileHandle> historyForward = new Array<>();

    /* loaded from: classes.dex */
    public interface FileHistoryCallback {
        FileHandle getCurrentDirectory();

        Stage getStage();

        void setDirectory(FileHandle fileHandle, FileChooser.HistoryPolicy historyPolicy);
    }

    public FileHistoryManager(FileChooserStyle style, FileHistoryCallback callback) {
        this.callback = callback;
        this.backButton = new VisImageButton(style.iconArrowLeft, FileChooserText.BACK.get());
        this.backButton.setGenerateDisabledImage(true);
        this.backButton.setDisabled(true);
        this.forwardButton = new VisImageButton(style.iconArrowRight, FileChooserText.FORWARD.get());
        this.forwardButton.setGenerateDisabledImage(true);
        this.forwardButton.setDisabled(true);
        this.buttonsTable = new VisTable(true);
        this.buttonsTable.add((VisTable) this.backButton);
        this.buttonsTable.add((VisTable) this.forwardButton);
        this.backButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileHistoryManager.this.historyBack();
            }
        });
        this.forwardButton.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                FileHistoryManager.this.historyForward();
            }
        });
    }

    public ClickListener getDefaultClickListener() {
        return new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileHistoryManager.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
                if (button == 3 || button == 4) {
                    return true;
                }
                return super.touchDown(event, x, y, pointer, button);
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
                if (button == 3 && FileHistoryManager.this.hasHistoryBack()) {
                    FileHistoryManager.this.historyBack();
                } else if (button == 4 && FileHistoryManager.this.hasHistoryForward()) {
                    FileHistoryManager.this.historyForward();
                } else {
                    super.touchUp(event, x, y, pointer, button);
                }
            }
        };
    }

    public VisTable getButtonsTable() {
        return this.buttonsTable;
    }

    public void historyClear() {
        this.history.clear();
        this.historyForward.clear();
        this.forwardButton.setDisabled(true);
        this.backButton.setDisabled(true);
    }

    public void historyAdd() {
        this.history.add(this.callback.getCurrentDirectory());
        this.historyForward.clear();
        this.backButton.setDisabled(false);
        this.forwardButton.setDisabled(true);
    }

    public void historyBack() {
        FileHandle dir = this.history.pop();
        this.historyForward.add(this.callback.getCurrentDirectory());
        if (!setDirectoryFromHistory(dir)) {
            this.historyForward.pop();
        }
        if (!hasHistoryBack()) {
            this.backButton.setDisabled(true);
        }
        this.forwardButton.setDisabled(false);
    }

    public void historyForward() {
        FileHandle dir = this.historyForward.pop();
        this.history.add(this.callback.getCurrentDirectory());
        if (!setDirectoryFromHistory(dir)) {
            this.history.pop();
        }
        if (!hasHistoryForward()) {
            this.forwardButton.setDisabled(true);
        }
        this.backButton.setDisabled(false);
    }

    private boolean setDirectoryFromHistory(FileHandle dir) {
        if (dir.exists()) {
            this.callback.setDirectory(dir, FileChooser.HistoryPolicy.IGNORE);
            return true;
        }
        Dialogs.showErrorDialog(this.callback.getStage(), FileChooserText.DIRECTORY_NO_LONGER_EXISTS.get());
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasHistoryForward() {
        return this.historyForward.size != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasHistoryBack() {
        return this.history.size != 0;
    }
}