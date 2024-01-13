package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.actions.Actions;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.file.FileChooser;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class DirsSuggestionPopup extends AbstractSuggestionPopup {
    private ExecutorService listDirExecutor;
    private Future<?> listDirFuture;
    private final VisTextField pathField;

    public DirsSuggestionPopup(FileChooser chooser, VisTextField pathField) {
        super(chooser);
        this.listDirExecutor = Executors.newSingleThreadExecutor(new ServiceThreadFactory("FileChooserListDirThread"));
        this.pathField = pathField;
    }

    public void pathFieldKeyTyped(Stage stage, float width) {
        if (this.pathField.getText().length() == 0) {
            remove();
        } else {
            createDirSuggestions(stage, width);
        }
    }

    private void createDirSuggestions(Stage stage, float width) {
        String pathFieldText = this.pathField.getText();
        addAction(Actions.sequence(Actions.delay(0.2f, Actions.removeActor())));
        Future<?> future = this.listDirFuture;
        if (future != null) {
            future.cancel(true);
        }
        this.listDirFuture = this.listDirExecutor.submit(new AnonymousClass1(pathFieldText, width, stage));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.kotcrab.vis.ui.widget.file.internal.DirsSuggestionPopup$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public class AnonymousClass1 implements Runnable {
        final /* synthetic */ String val$pathFieldText;
        final /* synthetic */ Stage val$stage;
        final /* synthetic */ float val$width;

        AnonymousClass1(String str, float f, Stage stage) {
            this.val$pathFieldText = str;
            this.val$width = f;
            this.val$stage = stage;
        }

        @Override // java.lang.Runnable
        public void run() {
            FileHandle listDir;
            final String partialPath;
            FileHandle enteredDir = Gdx.files.absolute(this.val$pathFieldText);
            if (enteredDir.exists()) {
                listDir = enteredDir;
                partialPath = BuildConfig.FLAVOR;
            } else {
                listDir = enteredDir.parent();
                partialPath = enteredDir.name();
            }
            final FileHandle[] files = listDir.list(DirsSuggestionPopup.this.chooser.getFileFilter());
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            Gdx.app.postRunnable(new Runnable() { // from class: com.kotcrab.vis.ui.widget.file.internal.DirsSuggestionPopup.1.1
                @Override // java.lang.Runnable
                public void run() {
                    FileHandle[] fileHandleArr;
                    DirsSuggestionPopup.this.clearChildren();
                    DirsSuggestionPopup.this.clearActions();
                    int suggestions = 0;
                    for (final FileHandle file : files) {
                        if (file.exists() && file.isDirectory() && file.name().startsWith(partialPath) && !file.name().equals(partialPath)) {
                            MenuItem item = DirsSuggestionPopup.this.createMenuItem(file.path());
                            item.getLabel().setEllipsis(true);
                            item.getLabelCell().width(AnonymousClass1.this.val$width - 20.0f);
                            DirsSuggestionPopup.this.addItem(item);
                            item.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.DirsSuggestionPopup.1.1.1
                                @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                                public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                                    DirsSuggestionPopup.this.chooser.setDirectory(file, FileChooser.HistoryPolicy.ADD);
                                }
                            });
                            suggestions++;
                            if (suggestions == 10) {
                                break;
                            }
                        }
                    }
                    if (suggestions != 0) {
                        DirsSuggestionPopup.this.showMenu(AnonymousClass1.this.val$stage, DirsSuggestionPopup.this.pathField);
                        DirsSuggestionPopup.this.setWidth(AnonymousClass1.this.val$width);
                        DirsSuggestionPopup.this.layout();
                        return;
                    }
                    DirsSuggestionPopup.this.remove();
                }
            });
        }
    }

    public void showRecentDirectories(Stage stage, Array<FileHandle> recentDirectories, float width) {
        int suggestions = createRecentDirSuggestions(recentDirectories, width);
        if (suggestions == 0) {
            remove();
            return;
        }
        showMenu(stage, this.pathField);
        setWidth(width);
        layout();
    }

    private int createRecentDirSuggestions(Array<FileHandle> files, float width) {
        clearChildren();
        int suggestions = 0;
        Iterator it = files.iterator();
        while (it.hasNext()) {
            final FileHandle file = (FileHandle) it.next();
            if (file.exists()) {
                MenuItem item = createMenuItem(file.path());
                item.getLabel().setEllipsis(true);
                item.getLabelCell().width(width - 20.0f);
                addItem(item);
                item.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.DirsSuggestionPopup.2
                    @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                    public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                        DirsSuggestionPopup.this.chooser.setDirectory(file, FileChooser.HistoryPolicy.ADD);
                    }
                });
                suggestions++;
                if (suggestions == 10) {
                    break;
                }
            }
        }
        return suggestions;
    }
}