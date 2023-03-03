package com.kotcrab.vis.ui.widget.color;

import com.badlogic.gdx.graphics.Color;

/* loaded from: classes.dex */
public interface ColorPickerListener {
    void canceled(Color color);

    void changed(Color color);

    void finished(Color color);

    void reset(Color color, Color color2);
}