package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.graphics.Color;

/* loaded from: classes.dex */
public class Highlighter extends BaseHighlighter {
    public void regex(Color color, String regex) {
        addRule(new RegexHighlightRule(color, regex));
    }
}