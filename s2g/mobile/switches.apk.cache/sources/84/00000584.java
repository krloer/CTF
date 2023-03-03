package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.scenes.scene2d.ui.ScrollPane;
import com.badlogic.gdx.utils.Array;
import com.kotcrab.vis.ui.util.highlight.BaseHighlighter;
import com.kotcrab.vis.ui.util.highlight.Highlight;
import com.kotcrab.vis.ui.widget.VisTextField;
import java.util.Iterator;

/* loaded from: classes.dex */
public class HighlightTextArea extends ScrollableTextArea {
    private boolean chunkUpdateScheduled;
    private Color defaultColor;
    private BaseHighlighter highlighter;
    private Array<Highlight> highlights;
    private float maxAreaHeight;
    private float maxAreaWidth;
    private Array<Chunk> renderChunks;

    public HighlightTextArea(String text) {
        super(text);
        this.highlights = new Array<>();
        this.renderChunks = new Array<>();
        this.chunkUpdateScheduled = true;
        this.defaultColor = Color.WHITE;
        this.maxAreaWidth = 0.0f;
        this.maxAreaHeight = 0.0f;
        this.softwrap = false;
    }

    public HighlightTextArea(String text, String styleName) {
        super(text, styleName);
        this.highlights = new Array<>();
        this.renderChunks = new Array<>();
        this.chunkUpdateScheduled = true;
        this.defaultColor = Color.WHITE;
        this.maxAreaWidth = 0.0f;
        this.maxAreaHeight = 0.0f;
    }

    public HighlightTextArea(String text, VisTextField.VisTextFieldStyle style) {
        super(text, style);
        this.highlights = new Array<>();
        this.renderChunks = new Array<>();
        this.chunkUpdateScheduled = true;
        this.defaultColor = Color.WHITE;
        this.maxAreaWidth = 0.0f;
        this.maxAreaHeight = 0.0f;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    void updateDisplayText() {
        super.updateDisplayText();
        processHighlighter();
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x00f3, code lost:
        r5 = r16;
     */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00ee A[LOOP:1: B:9:0x0040->B:38:0x00ee, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00f5 A[EDGE_INSN: B:55:0x00f5->B:41:0x00f5 ?: BREAK  , SYNTHETIC] */
    @Override // com.kotcrab.vis.ui.widget.VisTextArea, com.kotcrab.vis.ui.widget.VisTextField
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected void calculateOffsets() {
        /*
            Method dump skipped, instructions count: 313
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.kotcrab.vis.ui.widget.HighlightTextArea.calculateOffsets():void");
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextArea, com.kotcrab.vis.ui.widget.VisTextField
    protected void drawText(Batch batch, BitmapFont font, float x, float y) {
        this.maxAreaHeight = 0.0f;
        float offsetY = 0.0f;
        for (int i = this.firstLineShowing * 2; i < (this.firstLineShowing + this.linesShowing) * 2 && i < this.linesBreak.size; i += 2) {
            Iterator it = this.renderChunks.iterator();
            while (it.hasNext()) {
                Chunk chunk = (Chunk) it.next();
                if (chunk.lineIndex == i) {
                    font.setColor(chunk.color);
                    font.draw(batch, chunk.text, chunk.offsetX + x, y + offsetY);
                }
            }
            offsetY -= font.getLineHeight();
            this.maxAreaHeight += font.getLineHeight();
        }
        this.maxAreaHeight += 30.0f;
    }

    public void processHighlighter() {
        Array<Highlight> array = this.highlights;
        if (array == null) {
            return;
        }
        array.clear();
        BaseHighlighter baseHighlighter = this.highlighter;
        if (baseHighlighter != null) {
            baseHighlighter.process(this, this.highlights);
        }
        this.chunkUpdateScheduled = true;
    }

    public void setHighlighter(BaseHighlighter highlighter) {
        this.highlighter = highlighter;
        processHighlighter();
    }

    public BaseHighlighter getHighlighter() {
        return this.highlighter;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        return this.maxAreaWidth + 5.0f;
    }

    @Override // com.kotcrab.vis.ui.widget.ScrollableTextArea, com.kotcrab.vis.ui.widget.VisTextArea, com.kotcrab.vis.ui.widget.VisTextField, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        return this.maxAreaHeight + 5.0f;
    }

    @Override // com.kotcrab.vis.ui.widget.ScrollableTextArea
    public ScrollPane createCompatibleScrollPane() {
        ScrollPane scrollPane = super.createCompatibleScrollPane();
        scrollPane.setScrollingDisabled(false, false);
        return scrollPane;
    }

    /* loaded from: classes.dex */
    private static class Chunk {
        Color color;
        int lineIndex;
        float offsetX;
        String text;

        public Chunk(String text, Color color, float offsetX, int lineIndex) {
            this.text = text;
            this.color = color;
            this.offsetX = offsetX;
            this.lineIndex = lineIndex;
        }
    }
}