package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public abstract class SingleFileChooserListener implements FileChooserListener {
    protected abstract void selected(FileHandle fileHandle);

    @Override // com.kotcrab.vis.ui.widget.file.FileChooserListener
    public final void selected(Array<FileHandle> files) {
        selected(files.first());
    }

    @Override // com.kotcrab.vis.ui.widget.file.FileChooserListener
    public void canceled() {
    }
}