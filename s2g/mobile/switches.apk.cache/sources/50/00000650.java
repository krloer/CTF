package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class StreamingFileChooserListener implements FileChooserListener {
    public abstract void selected(FileHandle fileHandle);

    @Override // com.kotcrab.vis.ui.widget.file.FileChooserListener
    public final void selected(Array<FileHandle> files) {
        begin();
        Iterator it = files.iterator();
        while (it.hasNext()) {
            FileHandle file = (FileHandle) it.next();
            selected(file);
        }
        end();
    }

    public void begin() {
    }

    public void end() {
    }

    @Override // com.kotcrab.vis.ui.widget.file.FileChooserListener
    public void canceled() {
    }
}