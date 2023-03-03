package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.VisTextField;
import com.kotcrab.vis.ui.widget.file.FileChooser;
import com.kotcrab.vis.ui.widget.file.FileTypeFilter;
import java.util.Iterator;

/* loaded from: classes.dex */
public class FileSuggestionPopup extends AbstractSuggestionPopup {
    public FileSuggestionPopup(FileChooser chooser) {
        super(chooser);
    }

    public void pathFieldKeyTyped(Stage stage, Array<FileHandle> files, VisTextField pathField) {
        if (pathField.getText().length() == 0) {
            remove();
            return;
        }
        int suggestions = createSuggestions(files, pathField);
        if (suggestions == 0) {
            remove();
        } else {
            showMenu(stage, pathField);
        }
    }

    private int createSuggestions(Array<FileHandle> files, final VisTextField fileNameField) {
        clearChildren();
        int suggestions = 0;
        Iterator it = files.iterator();
        while (it.hasNext()) {
            final FileHandle file = (FileHandle) it.next();
            if (file.name().startsWith(fileNameField.getText()) && !file.name().equals(fileNameField.getText())) {
                MenuItem item = createMenuItem(getTrimmedName(file.name()));
                item.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileSuggestionPopup.1
                    @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                    public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                        FileSuggestionPopup.this.chooser.highlightFiles(file);
                    }
                });
                addItem(item);
                suggestions++;
            }
            if (suggestions == 10) {
                break;
            }
        }
        if (this.chooser.getMode() == FileChooser.Mode.SAVE && suggestions == 0 && this.chooser.getActiveFileTypeFilterRule() != null && fileNameField.getText().matches(".*\\.")) {
            FileTypeFilter.Rule rule = this.chooser.getActiveFileTypeFilterRule();
            Iterator it2 = rule.getExtensions().iterator();
            while (it2.hasNext()) {
                String extension = (String) it2.next();
                MenuItem item2 = createMenuItem(fileNameField.getText() + extension);
                final String arbitraryPath = fileNameField.getText() + extension;
                item2.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FileSuggestionPopup.2
                    @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
                    public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                        fileNameField.setText(arbitraryPath);
                        fileNameField.setCursorAtTextEnd();
                    }
                });
                addItem(item2);
                suggestions++;
            }
        }
        return suggestions;
    }

    private String getTrimmedName(String name) {
        if (name.length() > 40) {
            return name.substring(0, 40) + "...";
        }
        return name;
    }
}