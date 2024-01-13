package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.HighlightTextArea;

/* loaded from: classes.dex */
public class WordHighlightRule implements HighlightRule {
    private Color color;
    private String word;

    public WordHighlightRule(Color color, String word) {
        this.color = color;
        this.word = word;
    }

    @Override // com.kotcrab.vis.ui.util.highlight.HighlightRule
    public void process(HighlightTextArea textArea, Array<Highlight> highlights) {
        String text = textArea.getText();
        int index = text.indexOf(this.word);
        while (index >= 0) {
            Color color = this.color;
            int index2 = this.word.length() + index;
            highlights.add(new Highlight(color, index, index2));
            index = text.indexOf(this.word, index2);
        }
    }
}