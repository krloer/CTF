package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.Files;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.PopupMenu;
import com.kotcrab.vis.ui.widget.file.FileChooser;
import com.kotcrab.vis.ui.widget.file.FileChooserStyle;
import com.kotcrab.vis.ui.widget.file.FileUtils;
import java.io.File;
import java.io.IOException;

/* loaded from: classes.dex */
public class FilePopupMenu extends PopupMenu {
    private MenuItem addToFavorites;
    private MenuItem delete;
    private FileHandle file;
    private MenuItem newDirectory;
    private MenuItem refresh;
    private MenuItem removeFromFavorites;
    private MenuItem showInExplorer;
    private MenuItem sortBy;
    private SortingPopupMenu sortingPopupMenu;
    private final FileChooserStyle style;

    /* loaded from: classes.dex */
    public interface FilePopupMenuCallback {
        void showFileDelDialog(FileHandle fileHandle);

        void showNewDirDialog();
    }

    public FilePopupMenu(final FileChooser chooser, final FilePopupMenuCallback callback) {
        super(chooser.getChooserStyle().popupMenuStyle);
        this.style = chooser.getChooserStyle();
        this.sortingPopupMenu = new SortingPopupMenu(chooser);
        this.delete = new MenuItem(FileChooserText.CONTEXT_MENU_DELETE.get(), this.style.iconTrash);
        this.newDirectory = new MenuItem(FileChooserText.CONTEXT_MENU_NEW_DIRECTORY.get(), this.style.iconFolderNew);
        this.showInExplorer = new MenuItem(FileChooserText.CONTEXT_MENU_SHOW_IN_EXPLORER.get());
        this.refresh = new MenuItem(FileChooserText.CONTEXT_MENU_REFRESH.get(), this.style.iconRefresh);
        this.addToFavorites = new MenuItem(FileChooserText.CONTEXT_MENU_ADD_TO_FAVORITES.get(), this.style.iconFolderStar);
        this.removeFromFavorites = new MenuItem(FileChooserText.CONTEXT_MENU_REMOVE_FROM_FAVORITES.get(), this.style.iconFolderStar);
        this.sortBy = new MenuItem(FileChooserText.CONTEXT_MENU_SORT_BY.get());
        this.sortBy.setSubMenu(this.sortingPopupMenu);
        this.delete.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                callback.showFileDelDialog(FilePopupMenu.this.file);
            }
        });
        this.newDirectory.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                callback.showNewDirDialog();
            }
        });
        this.showInExplorer.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                try {
                    FileUtils.showDirInExplorer(FilePopupMenu.this.file);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        this.refresh.addListener(new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.4
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.refresh();
            }
        });
        this.addToFavorites.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.5
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                chooser.addFavorite(FilePopupMenu.this.file);
            }
        });
        this.removeFromFavorites.addListener(new ClickListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.FilePopupMenu.6
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
            public void clicked(InputEvent event, float x, float y) {
                chooser.removeFavorite(FilePopupMenu.this.file);
            }
        });
    }

    public void build() {
        this.sortingPopupMenu.build();
        clearChildren();
        addItem(this.newDirectory);
        addItem(this.sortBy);
        addItem(this.refresh);
    }

    public void build(Array<FileHandle> favorites, FileHandle file) {
        this.sortingPopupMenu.build();
        this.file = file;
        clearChildren();
        addItem(this.newDirectory);
        addItem(this.sortBy);
        addItem(this.refresh);
        addSeparator();
        if (file.type() == Files.FileType.Absolute || file.type() == Files.FileType.External) {
            addItem(this.delete);
        }
        if (file.type() == Files.FileType.Absolute) {
            addItem(this.showInExplorer);
            if (file.isDirectory()) {
                if (favorites.contains(file, false)) {
                    addItem(this.removeFromFavorites);
                } else {
                    addItem(this.addToFavorites);
                }
            }
        }
    }

    public void buildForFavorite(Array<FileHandle> favorites, File file) {
        this.file = Gdx.files.absolute(file.getAbsolutePath());
        clearChildren();
        addItem(this.showInExplorer);
        if (favorites.contains(this.file, false)) {
            addItem(this.removeFromFavorites);
        }
    }

    public boolean isAddedToStage() {
        return getStage() != null;
    }

    public void fileDeleterChanged(boolean trashAvailable) {
        this.delete.setText((trashAvailable ? FileChooserText.CONTEXT_MENU_MOVE_TO_TRASH : FileChooserText.CONTEXT_MENU_DELETE).get());
    }
}