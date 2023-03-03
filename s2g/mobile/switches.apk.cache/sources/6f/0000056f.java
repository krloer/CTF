package com.kotcrab.vis.ui.util.highlight;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.widget.HighlightTextArea;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public class RegexHighlightRule implements HighlightRule {
    private Color color;
    private Pattern pattern;

    public RegexHighlightRule(Color color, String regex) {
        this.color = color;
        this.pattern = Pattern.compile(regex);
    }

    @Override // com.kotcrab.vis.ui.util.highlight.HighlightRule
    public void process(HighlightTextArea textArea, Array<Highlight> highlights) {
        Matcher matcher = this.pattern.matcher(textArea.getText());
        while (matcher.find()) {
            highlights.add(new Highlight(this.color, matcher.start(), matcher.end()));
        }
    }
}