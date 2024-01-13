package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.HighlightTextArea;

/* loaded from: classes.dex */
public interface HighlightRule {
    void process(HighlightTextArea highlightTextArea, Array<Highlight> array);
}