package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.ui.Image;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.Scaling;
import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.PopupMenu;
import com.kotcrab.vis.ui.widget.file.FileChooser;

/* loaded from: classes.dex */
public class SortingPopupMenu extends PopupMenu {
    private final FileChooser chooser;
    private final Drawable selectedMenuItem;
    private MenuItem sortByAscending;
    private Image sortByAscendingImage;
    private MenuItem sortByDate;
    private Image sortByDateImage;
    private MenuItem sortByDescending;
    private Image sortByDescendingImage;
    private MenuItem sortByName;
    private Image sortByNameImage;
    private MenuItem sortBySize;
    private Image sortBySizeImage;

    public SortingPopupMenu(final FileChooser chooser) {
        this.selectedMenuItem = chooser.getChooserStyle().contextMenuSelectedItem;
        this.chooser = chooser;
        MenuItem menuItem = new MenuItem(FileChooserText.SORT_BY_NAME.get(), this.selectedMenuItem, new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.setSorting(FileChooser.FileSorting.NAME, true);
            }
        });
        this.sortByName = menuItem;
        addItem(menuItem);
        MenuItem menuItem2 = new MenuItem(FileChooserText.SORT_BY_DATE.get(), this.selectedMenuItem, new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu.2
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.setSorting(FileChooser.FileSorting.MODIFIED_DATE, false);
            }
        });
        this.sortByDate = menuItem2;
        addItem(menuItem2);
        MenuItem menuItem3 = new MenuItem(FileChooserText.SORT_BY_SIZE.get(), this.selectedMenuItem, new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu.3
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.setSorting(FileChooser.FileSorting.SIZE, true);
            }
        });
        this.sortBySize = menuItem3;
        addItem(menuItem3);
        addSeparator();
        MenuItem menuItem4 = new MenuItem(FileChooserText.SORT_BY_ASCENDING.get(), this.selectedMenuItem, new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu.4
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.setSortingOrderAscending(true);
            }
        });
        this.sortByAscending = menuItem4;
        addItem(menuItem4);
        MenuItem menuItem5 = new MenuItem(FileChooserText.SORT_BY_DESCENDING.get(), this.selectedMenuItem, new ChangeListener() { // from class: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu.5
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ChangeListener
            public void changed(ChangeListener.ChangeEvent event, Actor actor) {
                chooser.setSortingOrderAscending(false);
            }
        });
        this.sortByDescending = menuItem5;
        addItem(menuItem5);
        this.sortByNameImage = this.sortByName.getImage();
        this.sortByDateImage = this.sortByDate.getImage();
        this.sortBySizeImage = this.sortBySize.getImage();
        this.sortByAscendingImage = this.sortByAscending.getImage();
        this.sortByDescendingImage = this.sortByDescending.getImage();
        this.sortByNameImage.setScaling(Scaling.none);
        this.sortByDateImage.setScaling(Scaling.none);
        this.sortBySizeImage.setScaling(Scaling.none);
        this.sortByAscendingImage.setScaling(Scaling.none);
        this.sortByDescendingImage.setScaling(Scaling.none);
    }

    public void build() {
        this.sortByNameImage.setDrawable(null);
        this.sortByDateImage.setDrawable(null);
        this.sortBySizeImage.setDrawable(null);
        this.sortByAscendingImage.setDrawable(null);
        this.sortByDescendingImage.setDrawable(null);
        int i = AnonymousClass6.$SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$FileSorting[this.chooser.getSorting().ordinal()];
        if (i == 1) {
            this.sortByNameImage.setDrawable(this.selectedMenuItem);
        } else if (i == 2) {
            this.sortByDateImage.setDrawable(this.selectedMenuItem);
        } else if (i == 3) {
            this.sortBySizeImage.setDrawable(this.selectedMenuItem);
        }
        if (this.chooser.isSortingOrderAscending()) {
            this.sortByAscendingImage.setDrawable(this.selectedMenuItem);
        } else {
            this.sortByDescendingImage.setDrawable(this.selectedMenuItem);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.kotcrab.vis.ui.widget.file.internal.SortingPopupMenu$6  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass6 {
        static final /* synthetic */ int[] $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$FileSorting = new int[FileChooser.FileSorting.values().length];

        static {
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$FileSorting[FileChooser.FileSorting.NAME.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$FileSorting[FileChooser.FileSorting.MODIFIED_DATE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$kotcrab$vis$ui$widget$file$FileChooser$FileSorting[FileChooser.FileSorting.SIZE.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }
}