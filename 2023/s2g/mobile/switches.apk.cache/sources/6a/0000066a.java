package com.kotcrab.vis.ui.widget.file.internal;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import com.kotcrab.vis.ui.layout.GridGroup;
import com.kotcrab.vis.ui.util.adapter.ArrayAdapter;
import com.kotcrab.vis.ui.widget.VisTable;
import com.kotcrab.vis.ui.widget.file.FileChooser;

/* loaded from: classes.dex */
public class FileListAdapter extends ArrayAdapter<FileHandle, FileChooser.FileItem> {
    private final FileChooser chooser;
    private GridGroup gridGroup;
    private final Array<FileChooser.FileItem> orderedViews;

    public FileListAdapter(FileChooser chooser, Array<FileHandle> files) {
        super(files);
        this.orderedViews = new Array<>();
        this.chooser = chooser;
        this.gridGroup = new GridGroup(128.0f, 2.0f);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.util.adapter.CachedItemAdapter
    public FileChooser.FileItem createView(FileHandle item) {
        FileChooser fileChooser = this.chooser;
        fileChooser.getClass();
        return new FileChooser.FileItem(item, this.chooser.getViewMode());
    }

    @Override // com.kotcrab.vis.ui.util.adapter.AbstractListAdapter, com.kotcrab.vis.ui.util.adapter.ListAdapter
    public void fillTable(VisTable itemsTable) {
        getViews().clear();
        this.orderedViews.clear();
        this.gridGroup.clear();
        if (getItemsSorter() != null) {
            sort(getItemsSorter());
        }
        FileChooser.ViewMode viewMode = this.chooser.getViewMode();
        if (viewMode.isGridMode()) {
            viewMode.setupGridGroup(this.chooser.getSizes(), this.gridGroup);
            for (FileHandle item : iterable()) {
                FileChooser.FileItem view = (FileChooser.FileItem) getView(item);
                this.orderedViews.add(view);
                prepareViewBeforeAddingToTable(item, view);
                this.gridGroup.addActor(view);
            }
            itemsTable.add((VisTable) this.gridGroup).growX().minWidth(0.0f);
            return;
        }
        for (FileHandle item2 : iterable()) {
            FileChooser.FileItem view2 = (FileChooser.FileItem) getView(item2);
            this.orderedViews.add(view2);
            prepareViewBeforeAddingToTable(item2, view2);
            itemsTable.add((VisTable) view2).growX();
            itemsTable.row();
        }
    }

    @Override // com.kotcrab.vis.ui.util.adapter.CachedItemAdapter
    public ObjectMap<FileHandle, FileChooser.FileItem> getViews() {
        return super.getViews();
    }

    public Array<FileChooser.FileItem> getOrderedViews() {
        return this.orderedViews;
    }
}