package com.kotcrab.vis.ui.widget.file;

import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.utils.Array;

/* loaded from: classes.dex */
public interface FileChooserListener {
    void canceled();

    void selected(Array<FileHandle> array);
}