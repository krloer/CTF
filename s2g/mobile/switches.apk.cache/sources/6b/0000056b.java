package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.HighlightTextArea;
import java.util.Iterator;

/* loaded from: classes.dex */
public class BaseHighlighter {
    private Array<HighlightRule> rules = new Array<>();

    public void addRule(HighlightRule rule) {
        this.rules.add(rule);
    }

    public void word(Color color, String word) {
        addRule(new WordHighlightRule(color, word));
    }

    public void word(Color color, String... words) {
        for (String word : words) {
            addRule(new WordHighlightRule(color, word));
        }
    }

    public void process(HighlightTextArea textArea, Array<Highlight> highlights) {
        Iterator it = this.rules.iterator();
        while (it.hasNext()) {
            HighlightRule rule = (HighlightRule) it.next();
            rule.process(textArea, highlights);
        }
    }
}