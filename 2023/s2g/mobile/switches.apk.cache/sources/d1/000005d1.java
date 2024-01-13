package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;
import com.kotcrab.vis.ui.widget.VisTextField;

/* loaded from: classes.dex */
public class VisTextArea extends VisTextField {
    int cursorLine;
    float cursorX;
    int firstLineShowing;
    private String lastText;
    IntArray linesBreak;
    int linesShowing;
    float moveOffset;
    private float prefRows;
    boolean softwrap;

    public VisTextArea() {
        this.softwrap = true;
    }

    public VisTextArea(String text, String styleName) {
        super(text, styleName);
        this.softwrap = true;
    }

    public VisTextArea(String text, VisTextField.VisTextFieldStyle style) {
        super(text, style);
        this.softwrap = true;
    }

    public VisTextArea(String text) {
        super(text);
        this.softwrap = true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void initialize() {
        super.initialize();
        this.writeEnters = true;
        this.linesBreak = new IntArray();
        this.cursorLine = 0;
        this.firstLineShowing = 0;
        this.moveOffset = -1.0f;
        this.linesShowing = 0;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected int letterUnderCursor(float x) {
        if (this.linesBreak.size > 0) {
            if (this.cursorLine * 2 >= this.linesBreak.size) {
                return this.text.length();
            }
            float[] glyphPositions = this.glyphPositions.items;
            int start = this.linesBreak.items[this.cursorLine * 2];
            float x2 = x + glyphPositions[start];
            int end = this.linesBreak.items[(this.cursorLine * 2) + 1];
            int i = start;
            while (i < end && glyphPositions[i] <= x2) {
                i++;
            }
            if (glyphPositions[i] - x2 <= x2 - glyphPositions[i - 1]) {
                return Math.min(i, this.text.length());
            }
            return Math.max(0, i - 1);
        }
        return 0;
    }

    public void setPrefRows(float prefRows) {
        this.prefRows = prefRows;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField, com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        if (this.prefRows <= 0.0f) {
            return super.getPrefHeight();
        }
        float prefHeight = this.textHeight * this.prefRows;
        if (this.style.background != null) {
            return Math.max(this.style.background.getBottomHeight() + prefHeight + this.style.background.getTopHeight(), this.style.background.getMinHeight());
        }
        return prefHeight;
    }

    public int getLines() {
        return (this.linesBreak.size / 2) + (newLineAtEnd() ? 1 : 0);
    }

    public boolean newLineAtEnd() {
        return this.text.length() != 0 && (this.text.charAt(this.text.length() - 1) == '\n' || this.text.charAt(this.text.length() - 1) == '\r');
    }

    public void moveCursorLine(int line) {
        if (line < 0) {
            this.cursorLine = 0;
            this.cursor = 0;
            this.moveOffset = -1.0f;
        } else if (line >= getLines()) {
            int newLine = getLines() - 1;
            this.cursor = this.text.length();
            if (line > getLines() || newLine == this.cursorLine) {
                this.moveOffset = -1.0f;
            }
            this.cursorLine = newLine;
        } else if (line != this.cursorLine) {
            if (this.moveOffset < 0.0f) {
                this.moveOffset = this.linesBreak.size > this.cursorLine * 2 ? this.glyphPositions.get(this.cursor) - this.glyphPositions.get(this.linesBreak.get(this.cursorLine * 2)) : 0.0f;
            }
            this.cursorLine = line;
            this.cursor = this.cursorLine * 2 >= this.linesBreak.size ? this.text.length() : this.linesBreak.get(this.cursorLine * 2);
            while (this.cursor < this.text.length() && this.cursor <= this.linesBreak.get((this.cursorLine * 2) + 1) - 1 && this.glyphPositions.get(this.cursor) - this.glyphPositions.get(this.linesBreak.get(this.cursorLine * 2)) < this.moveOffset) {
                this.cursor++;
            }
            showCursor();
        }
    }

    void updateCurrentLine() {
        int index = calculateCurrentLineIndex(this.cursor);
        int line = index / 2;
        if (index % 2 == 0 || index + 1 >= this.linesBreak.size || this.cursor != this.linesBreak.items[index] || this.linesBreak.items[index + 1] != this.linesBreak.items[index]) {
            if (line < this.linesBreak.size / 2 || this.text.length() == 0 || this.text.charAt(this.text.length() - 1) == '\n' || this.text.charAt(this.text.length() - 1) == '\r') {
                this.cursorLine = line;
            }
        }
    }

    void showCursor() {
        updateCurrentLine();
        int i = this.cursorLine;
        int i2 = this.firstLineShowing;
        if (i == i2) {
            return;
        }
        int step = i >= i2 ? 1 : -1;
        while (true) {
            int i3 = this.firstLineShowing;
            int i4 = this.cursorLine;
            if (i3 > i4 || (i3 + this.linesShowing) - 1 < i4) {
                this.firstLineShowing += step;
            } else {
                return;
            }
        }
    }

    private int calculateCurrentLineIndex(int cursor) {
        int index = 0;
        while (index < this.linesBreak.size && cursor > this.linesBreak.items[index]) {
            index++;
        }
        return index;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void sizeChanged() {
        this.lastText = null;
        BitmapFont font = this.style.font;
        Drawable background = this.style.background;
        float availableHeight = getHeight() - (background == null ? 0.0f : background.getBottomHeight() + background.getTopHeight());
        this.linesShowing = (int) Math.floor(availableHeight / font.getLineHeight());
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected float getTextY(BitmapFont font, Drawable background) {
        float textY = getHeight();
        if (background != null) {
            return (int) (textY - background.getTopHeight());
        }
        return textY;
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected void drawSelection(Drawable selection, Batch batch, BitmapFont font, float x, float y) {
        float offsetY = 0.0f;
        int minIndex = Math.min(this.cursor, this.selectionStart);
        int maxIndex = Math.max(this.cursor, this.selectionStart);
        for (int i = this.firstLineShowing * 2; i + 1 < this.linesBreak.size && i < (this.firstLineShowing + this.linesShowing) * 2; i += 2) {
            int lineStart = this.linesBreak.get(i);
            int lineEnd = this.linesBreak.get(i + 1);
            if ((minIndex >= lineStart || minIndex >= lineEnd || maxIndex >= lineStart || maxIndex >= lineEnd) && (minIndex <= lineStart || minIndex <= lineEnd || maxIndex <= lineStart || maxIndex <= lineEnd)) {
                int start = Math.max(this.linesBreak.get(i), minIndex);
                int end = Math.min(this.linesBreak.get(i + 1), maxIndex);
                float selectionX = this.glyphPositions.get(start) - this.glyphPositions.get(this.linesBreak.get(i));
                float selectionWidth = this.glyphPositions.get(end) - this.glyphPositions.get(start);
                selection.draw(batch, x + selectionX + this.fontOffset, ((y - this.textHeight) - font.getDescent()) - offsetY, selectionWidth, font.getLineHeight());
            }
            offsetY += font.getLineHeight();
        }
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected void drawText(Batch batch, BitmapFont font, float x, float y) {
        float offsetY = 0.0f;
        for (int i = this.firstLineShowing * 2; i < (this.firstLineShowing + this.linesShowing) * 2 && i < this.linesBreak.size; i += 2) {
            font.draw(batch, this.displayText, x, y + offsetY, this.linesBreak.items[i], this.linesBreak.items[i + 1], 0.0f, 8, false);
            offsetY -= font.getLineHeight();
        }
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected void drawCursor(Drawable cursorPatch, Batch batch, BitmapFont font, float x, float y) {
        float textOffset;
        if (this.cursor >= this.glyphPositions.size || this.cursorLine * 2 >= this.linesBreak.size) {
            textOffset = 0.0f;
        } else {
            textOffset = this.glyphPositions.get(this.cursor) - this.glyphPositions.get(this.linesBreak.items[this.cursorLine * 2]);
        }
        this.cursorX = this.fontOffset + textOffset + font.getData().cursorX;
        cursorPatch.draw(batch, x + this.cursorX, (y - (font.getDescent() / 2.0f)) - (((this.cursorLine - this.firstLineShowing) + 1) * font.getLineHeight()), cursorPatch.getMinWidth(), font.getLineHeight());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void calculateOffsets() {
        super.calculateOffsets();
        if (!this.text.equals(this.lastText)) {
            this.lastText = this.text;
            BitmapFont font = this.style.font;
            float maxWidthLine = getWidth() - (this.style.background != null ? this.style.background.getLeftWidth() + this.style.background.getRightWidth() : 0.0f);
            this.linesBreak.clear();
            int lineStart = 0;
            int lastSpace = 0;
            Pool<GlyphLayout> layoutPool = Pools.get(GlyphLayout.class);
            GlyphLayout layout = layoutPool.obtain();
            for (int i = 0; i < this.text.length(); i++) {
                char lastCharacter = this.text.charAt(i);
                if (lastCharacter == '\r' || lastCharacter == '\n') {
                    this.linesBreak.add(lineStart);
                    this.linesBreak.add(i);
                    lineStart = i + 1;
                } else {
                    lastSpace = continueCursor(i, 0) ? lastSpace : i;
                    layout.setText(font, this.text.subSequence(lineStart, i + 1));
                    if (layout.width > maxWidthLine && this.softwrap) {
                        if (lineStart >= lastSpace) {
                            lastSpace = i - 1;
                        }
                        this.linesBreak.add(lineStart);
                        this.linesBreak.add(lastSpace + 1);
                        lineStart = lastSpace + 1;
                        lastSpace = lineStart;
                    }
                }
            }
            layoutPool.free(layout);
            if (lineStart < this.text.length()) {
                this.linesBreak.add(lineStart);
                this.linesBreak.add(this.text.length());
            }
            showCursor();
        }
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    protected InputListener createInputListener() {
        return new TextAreaListener();
    }

    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void setSelection(int selectionStart, int selectionEnd) {
        super.setSelection(selectionStart, selectionEnd);
        updateCurrentLine();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public void moveCursor(boolean forward, boolean jump) {
        int count = forward ? 1 : -1;
        int index = (this.cursorLine * 2) + count;
        if (index >= 0 && index + 1 < this.linesBreak.size && this.linesBreak.items[index] == this.cursor && this.linesBreak.items[index + 1] == this.cursor) {
            this.cursorLine += count;
            if (jump) {
                super.moveCursor(forward, jump);
            }
            showCursor();
        } else {
            super.moveCursor(forward, jump);
        }
        updateCurrentLine();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.kotcrab.vis.ui.widget.VisTextField
    public boolean continueCursor(int index, int offset) {
        int pos = calculateCurrentLineIndex(index + offset);
        return super.continueCursor(index, offset) && (pos < 0 || pos >= this.linesBreak.size + (-2) || this.linesBreak.items[pos + 1] != index || this.linesBreak.items[pos + 1] == this.linesBreak.items[pos + 2]);
    }

    public int getCursorLine() {
        return this.cursorLine;
    }

    public int getFirstLineShowing() {
        return this.firstLineShowing;
    }

    public int getLinesShowing() {
        return this.linesShowing;
    }

    public float getCursorX() {
        return this.cursorX;
    }

    public float getCursorY() {
        BitmapFont font = this.style.font;
        return -(((-font.getDescent()) / 2.0f) - (((this.cursorLine - this.firstLineShowing) + 1) * font.getLineHeight()));
    }

    /* loaded from: classes.dex */
    public class TextAreaListener extends VisTextField.TextFieldClickListener {
        public TextAreaListener() {
            super();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener
        public void setCursorPosition(float x, float y) {
            VisTextArea visTextArea = VisTextArea.this;
            visTextArea.moveOffset = -1.0f;
            Drawable background = visTextArea.style.background;
            BitmapFont font = VisTextArea.this.style.font;
            float height = VisTextArea.this.getHeight();
            if (background != null) {
                height -= background.getTopHeight();
                x -= background.getLeftWidth();
            }
            float x2 = Math.max(0.0f, x);
            if (background != null) {
                y -= background.getTopHeight();
            }
            VisTextArea.this.cursorLine = ((int) Math.floor((height - y) / font.getLineHeight())) + VisTextArea.this.firstLineShowing;
            VisTextArea visTextArea2 = VisTextArea.this;
            visTextArea2.cursorLine = Math.max(0, Math.min(visTextArea2.cursorLine, VisTextArea.this.getLines() - 1));
            super.setCursorPosition(x2, y);
            VisTextArea.this.updateCurrentLine();
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyDown(InputEvent event, int keycode) {
            boolean result = super.keyDown(event, keycode);
            Stage stage = VisTextArea.this.getStage();
            if (stage != null && stage.getKeyboardFocus() == VisTextArea.this) {
                boolean repeat = false;
                boolean shift = UIUtils.shift();
                if (keycode == 20) {
                    if (shift) {
                        if (!VisTextArea.this.hasSelection) {
                            VisTextArea visTextArea = VisTextArea.this;
                            visTextArea.selectionStart = visTextArea.cursor;
                            VisTextArea.this.hasSelection = true;
                        }
                    } else {
                        VisTextArea.this.clearSelection();
                    }
                    VisTextArea visTextArea2 = VisTextArea.this;
                    visTextArea2.moveCursorLine(visTextArea2.cursorLine + 1);
                    repeat = true;
                } else if (keycode == 19) {
                    if (shift) {
                        if (!VisTextArea.this.hasSelection) {
                            VisTextArea visTextArea3 = VisTextArea.this;
                            visTextArea3.selectionStart = visTextArea3.cursor;
                            VisTextArea.this.hasSelection = true;
                        }
                    } else {
                        VisTextArea.this.clearSelection();
                    }
                    VisTextArea visTextArea4 = VisTextArea.this;
                    visTextArea4.moveCursorLine(visTextArea4.cursorLine - 1);
                    repeat = true;
                } else {
                    VisTextArea.this.moveOffset = -1.0f;
                }
                if (repeat) {
                    scheduleKeyRepeatTask(keycode);
                }
                VisTextArea.this.showCursor();
                return true;
            }
            return result;
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyTyped(InputEvent event, char character) {
            boolean result = super.keyTyped(event, character);
            VisTextArea.this.showCursor();
            return result;
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener
        protected void goHome(boolean jump) {
            if (jump) {
                VisTextArea.this.cursor = 0;
            } else if (VisTextArea.this.cursorLine * 2 < VisTextArea.this.linesBreak.size) {
                VisTextArea visTextArea = VisTextArea.this;
                visTextArea.cursor = visTextArea.linesBreak.get(VisTextArea.this.cursorLine * 2);
            }
        }

        @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldClickListener
        protected void goEnd(boolean jump) {
            if (jump || VisTextArea.this.cursorLine >= VisTextArea.this.getLines()) {
                VisTextArea visTextArea = VisTextArea.this;
                visTextArea.cursor = visTextArea.text.length();
            } else if ((VisTextArea.this.cursorLine * 2) + 1 < VisTextArea.this.linesBreak.size) {
                VisTextArea visTextArea2 = VisTextArea.this;
                visTextArea2.cursor = visTextArea2.linesBreak.get((VisTextArea.this.cursorLine * 2) + 1);
            }
        }
    }
}