package com.kotcrab.vis.ui.widget.file.internal;

import com.kotcrab.vis.ui.widget.MenuItem;
import com.kotcrab.vis.ui.widget.PopupMenu;
import com.kotcrab.vis.ui.widget.file.FileChooser;

/* loaded from: classes.dex */
public class AbstractSuggestionPopup extends PopupMenu {
    public static final int MAX_SUGGESTIONS = 10;
    final FileChooser chooser;

    public AbstractSuggestionPopup(FileChooser chooser) {
        super(chooser.getChooserStyle().popupMenuStyle);
        this.chooser = chooser;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public MenuItem createMenuItem(String name) {
        MenuItem item = new MenuItem(name);
        item.getImageCell().size(0.0f);
        item.getShortcutCell().space(0.0f).pad(0.0f);
        item.getSubMenuIconCell().size(0.0f).space(0.0f).pad(0.0f);
        return item;
    }
}