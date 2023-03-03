package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Clipboard;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.Timer;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class TextField extends Widget implements Disableable {
    protected static final char BACKSPACE = '\b';
    protected static final char BULLET = 149;
    protected static final char CARRIAGE_RETURN = '\r';
    protected static final char DELETE = 127;
    protected static final char NEWLINE = '\n';
    protected static final char TAB = '\t';
    final Timer.Task blinkTask;
    float blinkTime;
    Clipboard clipboard;
    protected int cursor;
    boolean cursorOn;
    boolean disabled;
    protected CharSequence displayText;
    TextFieldFilter filter;
    boolean focusTraversal;
    boolean focused;
    protected float fontOffset;
    protected final FloatArray glyphPositions;
    protected boolean hasSelection;
    InputListener inputListener;
    final KeyRepeatTask keyRepeatTask;
    OnscreenKeyboard keyboard;
    long lastChangeTime;
    protected final GlyphLayout layout;
    TextFieldListener listener;
    private int maxLength;
    private String messageText;
    boolean onlyFontChars;
    private StringBuilder passwordBuffer;
    private char passwordCharacter;
    boolean passwordMode;
    boolean programmaticChangeEvents;
    float renderOffset;
    protected int selectionStart;
    private float selectionWidth;
    private float selectionX;
    TextFieldStyle style;
    protected String text;
    private int textHAlign;
    protected float textHeight;
    protected float textOffset;
    String undoText;
    private int visibleTextEnd;
    private int visibleTextStart;
    protected boolean writeEnters;
    private static final Vector2 tmp1 = new Vector2();
    private static final Vector2 tmp2 = new Vector2();
    private static final Vector2 tmp3 = new Vector2();
    public static float keyRepeatInitialTime = 0.4f;
    public static float keyRepeatTime = 0.1f;

    /* loaded from: classes.dex */
    public interface OnscreenKeyboard {
        void show(boolean z);
    }

    /* loaded from: classes.dex */
    public interface TextFieldListener {
        void keyTyped(TextField textField, char c);
    }

    public TextField(String text, Skin skin) {
        this(text, (TextFieldStyle) skin.get(TextFieldStyle.class));
    }

    public TextField(String text, Skin skin, String styleName) {
        this(text, (TextFieldStyle) skin.get(styleName, TextFieldStyle.class));
    }

    public TextField(String text, TextFieldStyle style) {
        this.layout = new GlyphLayout();
        this.glyphPositions = new FloatArray();
        this.keyboard = new DefaultOnscreenKeyboard();
        this.focusTraversal = true;
        this.onlyFontChars = true;
        this.textHAlign = 8;
        this.undoText = BuildConfig.FLAVOR;
        this.passwordCharacter = BULLET;
        this.blinkTime = 0.32f;
        this.blinkTask = new Timer.Task() { // from class: com.badlogic.gdx.scenes.scene2d.ui.TextField.1
            @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
            public void run() {
                if (TextField.this.getStage() == null) {
                    cancel();
                    return;
                }
                TextField textField = TextField.this;
                textField.cursorOn = !textField.cursorOn;
                Gdx.graphics.requestRendering();
            }
        };
        this.keyRepeatTask = new KeyRepeatTask();
        setStyle(style);
        this.clipboard = Gdx.app.getClipboard();
        initialize();
        setText(text);
        setSize(getPrefWidth(), getPrefHeight());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void initialize() {
        InputListener createInputListener = createInputListener();
        this.inputListener = createInputListener;
        addListener(createInputListener);
    }

    protected InputListener createInputListener() {
        return new TextFieldClickListener();
    }

    protected int letterUnderCursor(float x) {
        float x2 = x - (((this.textOffset + this.fontOffset) - this.style.font.getData().cursorX) - this.glyphPositions.get(this.visibleTextStart));
        Drawable background = getBackgroundDrawable();
        if (background != null) {
            x2 -= this.style.background.getLeftWidth();
        }
        int n = this.glyphPositions.size;
        float[] glyphPositions = this.glyphPositions.items;
        for (int i = 1; i < n; i++) {
            if (glyphPositions[i] > x2) {
                return glyphPositions[i] - x2 <= x2 - glyphPositions[i + (-1)] ? i : i - 1;
            }
        }
        int i2 = n - 1;
        return i2;
    }

    protected boolean isWordCharacter(char c) {
        return Character.isLetterOrDigit(c);
    }

    protected int[] wordUnderCursor(int at) {
        String text = this.text;
        int right = text.length();
        int left = 0;
        int index = at;
        if (at >= text.length()) {
            left = text.length();
            right = 0;
        } else {
            while (true) {
                if (index >= right) {
                    break;
                } else if (isWordCharacter(text.charAt(index))) {
                    index++;
                } else {
                    right = index;
                    break;
                }
            }
            int index2 = at - 1;
            while (true) {
                if (index2 <= -1) {
                    break;
                } else if (isWordCharacter(text.charAt(index2))) {
                    index2--;
                } else {
                    left = index2 + 1;
                    break;
                }
            }
        }
        return new int[]{left, right};
    }

    int[] wordUnderCursor(float x) {
        return wordUnderCursor(letterUnderCursor(x));
    }

    boolean withinMaxLength(int size) {
        int i = this.maxLength;
        return i <= 0 || size < i;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public int getMaxLength() {
        return this.maxLength;
    }

    public void setOnlyFontChars(boolean onlyFontChars) {
        this.onlyFontChars = onlyFontChars;
    }

    public void setStyle(TextFieldStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        this.textHeight = style.font.getCapHeight() - (style.font.getDescent() * 2.0f);
        if (this.text != null) {
            updateDisplayText();
        }
        invalidateHierarchy();
    }

    public TextFieldStyle getStyle() {
        return this.style;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void calculateOffsets() {
        float visibleWidth = getWidth();
        Drawable background = getBackgroundDrawable();
        if (background != null) {
            visibleWidth -= background.getLeftWidth() + background.getRightWidth();
        }
        int glyphCount = this.glyphPositions.size;
        float[] glyphPositions = this.glyphPositions.items;
        float f = glyphPositions[Math.max(0, this.cursor - 1)];
        float f2 = this.renderOffset;
        float distance = f + f2;
        if (distance <= 0.0f) {
            this.renderOffset = f2 - distance;
        } else {
            int index = Math.min(glyphCount - 1, this.cursor + 1);
            float minX = glyphPositions[index] - visibleWidth;
            if ((-this.renderOffset) < minX) {
                this.renderOffset = -minX;
            }
        }
        float maxOffset = 0.0f;
        float width = glyphPositions[glyphCount - 1];
        for (int i = glyphCount - 2; i >= 0; i--) {
            float x = glyphPositions[i];
            if (width - x > visibleWidth) {
                break;
            }
            maxOffset = x;
        }
        if ((-this.renderOffset) > maxOffset) {
            this.renderOffset = -maxOffset;
        }
        this.visibleTextStart = 0;
        float startX = 0.0f;
        int i2 = 0;
        while (true) {
            if (i2 < glyphCount) {
                if (glyphPositions[i2] < (-this.renderOffset)) {
                    i2++;
                } else {
                    this.visibleTextStart = i2;
                    startX = glyphPositions[i2];
                    break;
                }
            } else {
                break;
            }
        }
        int i3 = this.visibleTextStart;
        int end = i3 + 1;
        float endX = visibleWidth - this.renderOffset;
        int n = Math.min(this.displayText.length(), glyphCount);
        while (end <= n && glyphPositions[end] <= endX) {
            end++;
        }
        int n2 = end - 1;
        this.visibleTextEnd = Math.max(0, n2);
        int i4 = this.textHAlign;
        if ((i4 & 8) == 0) {
            this.textOffset = ((visibleWidth - glyphPositions[this.visibleTextEnd]) - this.fontOffset) + startX;
            if ((i4 & 1) != 0) {
                this.textOffset = Math.round(this.textOffset * 0.5f);
            }
        } else {
            this.textOffset = this.renderOffset + startX;
        }
        if (this.hasSelection) {
            int minIndex = Math.min(this.cursor, this.selectionStart);
            int maxIndex = Math.max(this.cursor, this.selectionStart);
            float minX2 = Math.max(glyphPositions[minIndex] - glyphPositions[this.visibleTextStart], -this.textOffset);
            float maxX = Math.min(glyphPositions[maxIndex] - glyphPositions[this.visibleTextStart], visibleWidth - this.textOffset);
            this.selectionX = minX2;
            this.selectionWidth = (maxX - minX2) - this.style.font.getData().cursorX;
        }
    }

    protected Drawable getBackgroundDrawable() {
        return (!this.disabled || this.style.disabledBackground == null) ? (this.style.focusedBackground == null || !hasKeyboardFocus()) ? this.style.background : this.style.focusedBackground : this.style.disabledBackground;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        boolean focused = hasKeyboardFocus();
        if (focused != this.focused || (focused && !this.blinkTask.isScheduled())) {
            this.focused = focused;
            this.blinkTask.cancel();
            this.cursorOn = focused;
            if (focused) {
                Timer.Task task = this.blinkTask;
                float f = this.blinkTime;
                Timer.schedule(task, f, f);
            } else {
                this.keyRepeatTask.cancel();
            }
        } else if (!focused) {
            this.cursorOn = false;
        }
        BitmapFont font = this.style.font;
        Color fontColor = (!this.disabled || this.style.disabledFontColor == null) ? (!focused || this.style.focusedFontColor == null) ? this.style.fontColor : this.style.focusedFontColor : this.style.disabledFontColor;
        Drawable selection = this.style.selection;
        Drawable cursorPatch = this.style.cursor;
        Drawable background = getBackgroundDrawable();
        Color color = getColor();
        float x = getX();
        float y = getY();
        float width = getWidth();
        float height = getHeight();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        float bgLeftWidth = 0.0f;
        float bgRightWidth = 0.0f;
        if (background != null) {
            background.draw(batch, x, y, width, height);
            bgLeftWidth = background.getLeftWidth();
            bgRightWidth = background.getRightWidth();
        }
        float textY = getTextY(font, background);
        calculateOffsets();
        if (focused && this.hasSelection && selection != null) {
            drawSelection(selection, batch, font, x + bgLeftWidth, y + textY);
        }
        float yOffset = font.isFlipped() ? -this.textHeight : 0.0f;
        if (this.displayText.length() == 0) {
            if (!focused && this.messageText != null) {
                BitmapFont messageFont = this.style.messageFont != null ? this.style.messageFont : font;
                if (this.style.messageFontColor != null) {
                    messageFont.setColor(this.style.messageFontColor.r, this.style.messageFontColor.g, this.style.messageFontColor.b, this.style.messageFontColor.a * color.a * parentAlpha);
                } else {
                    messageFont.setColor(0.7f, 0.7f, 0.7f, color.a * parentAlpha);
                }
                drawMessageText(batch, messageFont, x + bgLeftWidth, y + textY + yOffset, (width - bgLeftWidth) - bgRightWidth);
            }
        } else {
            font.setColor(fontColor.r, fontColor.g, fontColor.b, fontColor.a * color.a * parentAlpha);
            drawText(batch, font, x + bgLeftWidth, y + textY + yOffset);
        }
        if (!this.disabled && this.cursorOn && cursorPatch != null) {
            drawCursor(cursorPatch, batch, font, x + bgLeftWidth, y + textY);
        }
    }

    protected float getTextY(BitmapFont font, Drawable background) {
        float textY;
        float height = getHeight();
        float textY2 = (this.textHeight / 2.0f) + font.getDescent();
        if (background != null) {
            float bottom = background.getBottomHeight();
            textY = (((height - background.getTopHeight()) - bottom) / 2.0f) + textY2 + bottom;
        } else {
            textY = textY2 + (height / 2.0f);
        }
        return font.usesIntegerPositions() ? (int) textY : textY;
    }

    protected void drawSelection(Drawable selection, Batch batch, BitmapFont font, float x, float y) {
        selection.draw(batch, this.textOffset + x + this.selectionX + this.fontOffset, (y - this.textHeight) - font.getDescent(), this.selectionWidth, this.textHeight);
    }

    protected void drawText(Batch batch, BitmapFont font, float x, float y) {
        font.draw(batch, this.displayText, x + this.textOffset, y, this.visibleTextStart, this.visibleTextEnd, 0.0f, 8, false);
    }

    protected void drawMessageText(Batch batch, BitmapFont font, float x, float y, float maxWidth) {
        String str = this.messageText;
        font.draw(batch, str, x, y, 0, str.length(), maxWidth, this.textHAlign, false, "...");
    }

    protected void drawCursor(Drawable cursorPatch, Batch batch, BitmapFont font, float x, float y) {
        cursorPatch.draw(batch, (((this.textOffset + x) + this.glyphPositions.get(this.cursor)) - this.glyphPositions.get(this.visibleTextStart)) + this.fontOffset + font.getData().cursorX, (y - this.textHeight) - font.getDescent(), cursorPatch.getMinWidth(), this.textHeight);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateDisplayText() {
        BitmapFont font = this.style.font;
        BitmapFont.BitmapFontData data = font.getData();
        String text = this.text;
        int textLength = text.length();
        StringBuilder buffer = new StringBuilder();
        int i = 0;
        while (true) {
            char c = ' ';
            if (i >= textLength) {
                break;
            }
            char c2 = text.charAt(i);
            if (data.hasGlyph(c2)) {
                c = c2;
            }
            buffer.append(c);
            i++;
        }
        String newDisplayText = buffer.toString();
        if (this.passwordMode && data.hasGlyph(this.passwordCharacter)) {
            if (this.passwordBuffer == null) {
                this.passwordBuffer = new StringBuilder(newDisplayText.length());
            }
            if (this.passwordBuffer.length() > textLength) {
                this.passwordBuffer.setLength(textLength);
            } else {
                for (int i2 = this.passwordBuffer.length(); i2 < textLength; i2++) {
                    this.passwordBuffer.append(this.passwordCharacter);
                }
            }
            this.displayText = this.passwordBuffer;
        } else {
            this.displayText = newDisplayText;
        }
        this.layout.setText(font, this.displayText.toString().replace(CARRIAGE_RETURN, ' ').replace(NEWLINE, ' '));
        this.glyphPositions.clear();
        float x = 0.0f;
        if (this.layout.runs.size > 0) {
            GlyphLayout.GlyphRun run = this.layout.runs.first();
            FloatArray xAdvances = run.xAdvances;
            this.fontOffset = xAdvances.first();
            int n = xAdvances.size;
            for (int i3 = 1; i3 < n; i3++) {
                this.glyphPositions.add(x);
                x += xAdvances.get(i3);
            }
        } else {
            this.fontOffset = 0.0f;
        }
        this.glyphPositions.add(x);
        this.visibleTextStart = Math.min(this.visibleTextStart, this.glyphPositions.size - 1);
        this.visibleTextEnd = MathUtils.clamp(this.visibleTextEnd, this.visibleTextStart, this.glyphPositions.size - 1);
        if (this.selectionStart > newDisplayText.length()) {
            this.selectionStart = textLength;
        }
    }

    public void copy() {
        if (this.hasSelection && !this.passwordMode) {
            this.clipboard.setContents(this.text.substring(Math.min(this.cursor, this.selectionStart), Math.max(this.cursor, this.selectionStart)));
        }
    }

    public void cut() {
        cut(this.programmaticChangeEvents);
    }

    void cut(boolean fireChangeEvent) {
        if (this.hasSelection && !this.passwordMode) {
            copy();
            this.cursor = delete(fireChangeEvent);
            updateDisplayText();
        }
    }

    void paste(String content, boolean fireChangeEvent) {
        TextFieldFilter textFieldFilter;
        if (content == null) {
            return;
        }
        StringBuilder buffer = new StringBuilder();
        int textLength = this.text.length();
        if (this.hasSelection) {
            textLength -= Math.abs(this.cursor - this.selectionStart);
        }
        BitmapFont.BitmapFontData data = this.style.font.getData();
        int n = content.length();
        for (int i = 0; i < n && withinMaxLength(buffer.length() + textLength); i++) {
            char c = content.charAt(i);
            if ((this.writeEnters && (c == '\n' || c == '\r')) || (c != '\r' && c != '\n' && ((!this.onlyFontChars || data.hasGlyph(c)) && ((textFieldFilter = this.filter) == null || textFieldFilter.acceptChar(this, c))))) {
                buffer.append(c);
            }
        }
        String content2 = buffer.toString();
        if (this.hasSelection) {
            this.cursor = delete(fireChangeEvent);
        }
        if (fireChangeEvent) {
            String str = this.text;
            changeText(str, insert(this.cursor, content2, str));
        } else {
            this.text = insert(this.cursor, content2, this.text);
        }
        updateDisplayText();
        this.cursor += content2.length();
    }

    String insert(int position, CharSequence text, String to) {
        if (to.length() == 0) {
            return text.toString();
        }
        return to.substring(0, position) + ((Object) text) + to.substring(position, to.length());
    }

    int delete(boolean fireChangeEvent) {
        int from = this.selectionStart;
        int to = this.cursor;
        int minIndex = Math.min(from, to);
        int maxIndex = Math.max(from, to);
        StringBuilder sb = new StringBuilder();
        String str = BuildConfig.FLAVOR;
        sb.append(minIndex > 0 ? this.text.substring(0, minIndex) : BuildConfig.FLAVOR);
        if (maxIndex < this.text.length()) {
            String str2 = this.text;
            str = str2.substring(maxIndex, str2.length());
        }
        sb.append(str);
        String newText = sb.toString();
        if (fireChangeEvent) {
            changeText(this.text, newText);
        } else {
            this.text = newText;
        }
        clearSelection();
        return minIndex;
    }

    public void next(boolean up) {
        Stage stage = getStage();
        if (stage == null) {
            return;
        }
        TextField current = this;
        Vector2 currentCoords = current.getParent().localToStageCoordinates(tmp2.set(current.getX(), current.getY()));
        Vector2 bestCoords = tmp1;
        while (true) {
            TextField textField = current.findNextTextField(stage.getActors(), null, bestCoords, currentCoords, up);
            if (textField == null) {
                if (up) {
                    currentCoords.set(-3.4028235E38f, -3.4028235E38f);
                } else {
                    currentCoords.set(Float.MAX_VALUE, Float.MAX_VALUE);
                }
                textField = current.findNextTextField(stage.getActors(), null, bestCoords, currentCoords, up);
            }
            if (textField == null) {
                Gdx.input.setOnscreenKeyboardVisible(false);
                return;
            } else if (stage.setKeyboardFocus(textField)) {
                textField.selectAll();
                return;
            } else {
                current = textField;
                currentCoords.set(bestCoords);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x009c, code lost:
        if (((r2.y > r19.y) ^ r21) != false) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00b9, code lost:
        if (((r2.x < r19.x) ^ r21) != false) goto L51;
     */
    /* JADX WARN: Removed duplicated region for block: B:28:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0081 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00e2 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private com.badlogic.gdx.scenes.scene2d.ui.TextField findNextTextField(com.badlogic.gdx.utils.Array<com.badlogic.gdx.scenes.scene2d.Actor> r17, com.badlogic.gdx.scenes.scene2d.ui.TextField r18, com.badlogic.gdx.math.Vector2 r19, com.badlogic.gdx.math.Vector2 r20, boolean r21) {
        /*
            Method dump skipped, instructions count: 233
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.scenes.scene2d.ui.TextField.findNextTextField(com.badlogic.gdx.utils.Array, com.badlogic.gdx.scenes.scene2d.ui.TextField, com.badlogic.gdx.math.Vector2, com.badlogic.gdx.math.Vector2, boolean):com.badlogic.gdx.scenes.scene2d.ui.TextField");
    }

    public InputListener getDefaultInputListener() {
        return this.inputListener;
    }

    public void setTextFieldListener(TextFieldListener listener) {
        this.listener = listener;
    }

    public void setTextFieldFilter(TextFieldFilter filter) {
        this.filter = filter;
    }

    public TextFieldFilter getTextFieldFilter() {
        return this.filter;
    }

    public void setFocusTraversal(boolean focusTraversal) {
        this.focusTraversal = focusTraversal;
    }

    public String getMessageText() {
        return this.messageText;
    }

    public void setMessageText(String messageText) {
        this.messageText = messageText;
    }

    public void appendText(String str) {
        if (str == null) {
            str = BuildConfig.FLAVOR;
        }
        clearSelection();
        this.cursor = this.text.length();
        paste(str, this.programmaticChangeEvents);
    }

    public void setText(String str) {
        if (str == null) {
            str = BuildConfig.FLAVOR;
        }
        if (str.equals(this.text)) {
            return;
        }
        clearSelection();
        String oldText = this.text;
        this.text = BuildConfig.FLAVOR;
        paste(str, false);
        if (this.programmaticChangeEvents) {
            changeText(oldText, this.text);
        }
        this.cursor = 0;
    }

    public String getText() {
        return this.text;
    }

    boolean changeText(String oldText, String newText) {
        if (newText.equals(oldText)) {
            return false;
        }
        this.text = newText;
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        boolean cancelled = fire(changeEvent);
        if (cancelled) {
            this.text = oldText;
        }
        Pools.free(changeEvent);
        return !cancelled;
    }

    public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
        this.programmaticChangeEvents = programmaticChangeEvents;
    }

    public boolean getProgrammaticChangeEvents() {
        return this.programmaticChangeEvents;
    }

    public int getSelectionStart() {
        return this.selectionStart;
    }

    public String getSelection() {
        return this.hasSelection ? this.text.substring(Math.min(this.selectionStart, this.cursor), Math.max(this.selectionStart, this.cursor)) : BuildConfig.FLAVOR;
    }

    public void setSelection(int selectionStart, int selectionEnd) {
        if (selectionStart < 0) {
            throw new IllegalArgumentException("selectionStart must be >= 0");
        }
        if (selectionEnd < 0) {
            throw new IllegalArgumentException("selectionEnd must be >= 0");
        }
        int selectionStart2 = Math.min(this.text.length(), selectionStart);
        int selectionEnd2 = Math.min(this.text.length(), selectionEnd);
        if (selectionEnd2 == selectionStart2) {
            clearSelection();
            return;
        }
        if (selectionEnd2 < selectionStart2) {
            selectionEnd2 = selectionStart2;
            selectionStart2 = selectionEnd2;
        }
        this.hasSelection = true;
        this.selectionStart = selectionStart2;
        this.cursor = selectionEnd2;
    }

    public void selectAll() {
        setSelection(0, this.text.length());
    }

    public void clearSelection() {
        this.hasSelection = false;
    }

    public void setCursorPosition(int cursorPosition) {
        if (cursorPosition < 0) {
            throw new IllegalArgumentException("cursorPosition must be >= 0");
        }
        clearSelection();
        this.cursor = Math.min(cursorPosition, this.text.length());
    }

    public int getCursorPosition() {
        return this.cursor;
    }

    public OnscreenKeyboard getOnscreenKeyboard() {
        return this.keyboard;
    }

    public void setOnscreenKeyboard(OnscreenKeyboard keyboard) {
        this.keyboard = keyboard;
    }

    public void setClipboard(Clipboard clipboard) {
        this.clipboard = clipboard;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        return 150.0f;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        float topAndBottom = 0.0f;
        float minHeight = 0.0f;
        if (this.style.background != null) {
            topAndBottom = Math.max(0.0f, this.style.background.getBottomHeight() + this.style.background.getTopHeight());
            minHeight = Math.max(0.0f, this.style.background.getMinHeight());
        }
        if (this.style.focusedBackground != null) {
            topAndBottom = Math.max(topAndBottom, this.style.focusedBackground.getBottomHeight() + this.style.focusedBackground.getTopHeight());
            minHeight = Math.max(minHeight, this.style.focusedBackground.getMinHeight());
        }
        if (this.style.disabledBackground != null) {
            topAndBottom = Math.max(topAndBottom, this.style.disabledBackground.getBottomHeight() + this.style.disabledBackground.getTopHeight());
            minHeight = Math.max(minHeight, this.style.disabledBackground.getMinHeight());
        }
        return Math.max(this.textHeight + topAndBottom, minHeight);
    }

    public void setAlignment(int alignment) {
        this.textHAlign = alignment;
    }

    public int getAlignment() {
        return this.textHAlign;
    }

    public void setPasswordMode(boolean passwordMode) {
        this.passwordMode = passwordMode;
        updateDisplayText();
    }

    public boolean isPasswordMode() {
        return this.passwordMode;
    }

    public void setPasswordCharacter(char passwordCharacter) {
        this.passwordCharacter = passwordCharacter;
        if (this.passwordMode) {
            updateDisplayText();
        }
    }

    public void setBlinkTime(float blinkTime) {
        this.blinkTime = blinkTime;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public boolean isDisabled() {
        return this.disabled;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void moveCursor(boolean forward, boolean jump) {
        int limit = forward ? this.text.length() : 0;
        int charOffset = forward ? 0 : -1;
        do {
            int i = this.cursor;
            if (forward) {
                int i2 = i + 1;
                this.cursor = i2;
                if (i2 >= limit) {
                    return;
                }
            } else {
                int i3 = i - 1;
                this.cursor = i3;
                if (i3 <= limit) {
                    return;
                }
            }
            if (!jump) {
                return;
            }
        } while (continueCursor(this.cursor, charOffset));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean continueCursor(int index, int offset) {
        char c = this.text.charAt(index + offset);
        return isWordCharacter(c);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class KeyRepeatTask extends Timer.Task {
        int keycode;

        KeyRepeatTask() {
        }

        @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
        public void run() {
            if (TextField.this.getStage() == null) {
                cancel();
            } else {
                TextField.this.inputListener.keyDown(null, this.keycode);
            }
        }
    }

    /* loaded from: classes.dex */
    public interface TextFieldFilter {
        boolean acceptChar(TextField textField, char c);

        /* loaded from: classes.dex */
        public static class DigitsOnlyFilter implements TextFieldFilter {
            @Override // com.badlogic.gdx.scenes.scene2d.ui.TextField.TextFieldFilter
            public boolean acceptChar(TextField textField, char c) {
                return Character.isDigit(c);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class DefaultOnscreenKeyboard implements OnscreenKeyboard {
        @Override // com.badlogic.gdx.scenes.scene2d.ui.TextField.OnscreenKeyboard
        public void show(boolean visible) {
            Gdx.input.setOnscreenKeyboardVisible(visible);
        }
    }

    /* loaded from: classes.dex */
    public class TextFieldClickListener extends ClickListener {
        public TextFieldClickListener() {
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener
        public void clicked(InputEvent event, float x, float y) {
            int count = getTapCount() % 4;
            if (count == 0) {
                TextField.this.clearSelection();
            }
            if (count == 2) {
                int[] array = TextField.this.wordUnderCursor(x);
                TextField.this.setSelection(array[0], array[1]);
            }
            if (count == 3) {
                TextField.this.selectAll();
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
            if (super.touchDown(event, x, y, pointer, button)) {
                if (pointer != 0 || button == 0) {
                    if (TextField.this.disabled) {
                        return true;
                    }
                    setCursorPosition(x, y);
                    TextField textField = TextField.this;
                    textField.selectionStart = textField.cursor;
                    Stage stage = TextField.this.getStage();
                    if (stage != null) {
                        stage.setKeyboardFocus(TextField.this);
                    }
                    TextField.this.keyboard.show(true);
                    TextField.this.hasSelection = true;
                    return true;
                }
                return false;
            }
            return false;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public void touchDragged(InputEvent event, float x, float y, int pointer) {
            super.touchDragged(event, x, y, pointer);
            setCursorPosition(x, y);
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public void touchUp(InputEvent event, float x, float y, int pointer, int button) {
            if (TextField.this.selectionStart == TextField.this.cursor) {
                TextField.this.hasSelection = false;
            }
            super.touchUp(event, x, y, pointer, button);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public void setCursorPosition(float x, float y) {
            TextField textField = TextField.this;
            textField.cursor = textField.letterUnderCursor(x);
            TextField textField2 = TextField.this;
            textField2.cursorOn = textField2.focused;
            TextField.this.blinkTask.cancel();
            if (TextField.this.focused) {
                Timer.schedule(TextField.this.blinkTask, TextField.this.blinkTime, TextField.this.blinkTime);
            }
        }

        protected void goHome(boolean jump) {
            TextField.this.cursor = 0;
        }

        protected void goEnd(boolean jump) {
            TextField textField = TextField.this;
            textField.cursor = textField.text.length();
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyDown(InputEvent event, int keycode) {
            if (TextField.this.disabled) {
                return false;
            }
            TextField textField = TextField.this;
            textField.cursorOn = textField.focused;
            TextField.this.blinkTask.cancel();
            if (TextField.this.focused) {
                Timer.schedule(TextField.this.blinkTask, TextField.this.blinkTime, TextField.this.blinkTime);
            }
            if (TextField.this.hasKeyboardFocus()) {
                boolean repeat = false;
                boolean ctrl = UIUtils.ctrl();
                boolean jump = ctrl && !TextField.this.passwordMode;
                boolean handled = true;
                if (ctrl) {
                    if (keycode != 29) {
                        if (keycode != 31) {
                            if (keycode == 50) {
                                TextField textField2 = TextField.this;
                                textField2.paste(textField2.clipboard.getContents(), true);
                                repeat = true;
                            } else if (keycode == 52) {
                                TextField.this.cut(true);
                                return true;
                            } else if (keycode != 54) {
                                if (keycode != 124) {
                                    handled = false;
                                }
                            } else {
                                String oldText = TextField.this.text;
                                TextField textField3 = TextField.this;
                                textField3.setText(textField3.undoText);
                                TextField textField4 = TextField.this;
                                textField4.undoText = oldText;
                                textField4.updateDisplayText();
                                return true;
                            }
                        }
                        TextField.this.copy();
                        return true;
                    }
                    TextField.this.selectAll();
                    return true;
                }
                if (UIUtils.shift()) {
                    if (keycode == 112) {
                        TextField.this.cut(true);
                    } else if (keycode == 124) {
                        TextField textField5 = TextField.this;
                        textField5.paste(textField5.clipboard.getContents(), true);
                    }
                    int temp = TextField.this.cursor;
                    if (keycode == 3) {
                        goHome(jump);
                        handled = true;
                    } else if (keycode == 123) {
                        goEnd(jump);
                        handled = true;
                    } else if (keycode == 21) {
                        TextField.this.moveCursor(false, jump);
                        repeat = true;
                        handled = true;
                    } else if (keycode == 22) {
                        TextField.this.moveCursor(true, jump);
                        repeat = true;
                        handled = true;
                    }
                    if (!TextField.this.hasSelection) {
                        TextField textField6 = TextField.this;
                        textField6.selectionStart = temp;
                        textField6.hasSelection = true;
                    }
                } else if (keycode == 3) {
                    goHome(jump);
                    TextField.this.clearSelection();
                    handled = true;
                } else if (keycode == 123) {
                    goEnd(jump);
                    TextField.this.clearSelection();
                    handled = true;
                } else if (keycode == 21) {
                    TextField.this.moveCursor(false, jump);
                    TextField.this.clearSelection();
                    repeat = true;
                    handled = true;
                } else if (keycode == 22) {
                    TextField.this.moveCursor(true, jump);
                    TextField.this.clearSelection();
                    repeat = true;
                    handled = true;
                }
                TextField textField7 = TextField.this;
                textField7.cursor = MathUtils.clamp(textField7.cursor, 0, TextField.this.text.length());
                if (repeat) {
                    scheduleKeyRepeatTask(keycode);
                }
                return handled;
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public void scheduleKeyRepeatTask(int keycode) {
            if (!TextField.this.keyRepeatTask.isScheduled() || TextField.this.keyRepeatTask.keycode != keycode) {
                TextField.this.keyRepeatTask.keycode = keycode;
                TextField.this.keyRepeatTask.cancel();
                Timer.schedule(TextField.this.keyRepeatTask, TextField.keyRepeatInitialTime, TextField.keyRepeatTime);
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyUp(InputEvent event, int keycode) {
            if (TextField.this.disabled) {
                return false;
            }
            TextField.this.keyRepeatTask.cancel();
            return true;
        }

        protected boolean checkFocusTraversal(char character) {
            return TextField.this.focusTraversal && (character == '\t' || ((character == '\r' || character == '\n') && (UIUtils.isAndroid || UIUtils.isIos)));
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyTyped(InputEvent event, char character) {
            boolean add;
            if (TextField.this.disabled) {
                return false;
            }
            if (character != '\r') {
                switch (character) {
                    case '\b':
                    case '\t':
                    case '\n':
                        break;
                    default:
                        if (character < ' ') {
                            return false;
                        }
                        break;
                }
            }
            if (TextField.this.hasKeyboardFocus()) {
                if (UIUtils.isMac && Gdx.input.isKeyPressed(63)) {
                    return true;
                }
                if (checkFocusTraversal(character)) {
                    TextField.this.next(UIUtils.shift());
                } else {
                    boolean enter = character == '\r' || character == '\n';
                    boolean delete = character == 127;
                    boolean backspace = character == '\b';
                    TextField textField = TextField.this;
                    if (enter) {
                        add = textField.writeEnters;
                    } else {
                        add = !textField.onlyFontChars || TextField.this.style.font.getData().hasGlyph(character);
                    }
                    boolean remove = backspace || delete;
                    if (add || remove) {
                        String oldText = TextField.this.text;
                        int oldCursor = TextField.this.cursor;
                        if (remove) {
                            if (TextField.this.hasSelection) {
                                TextField textField2 = TextField.this;
                                textField2.cursor = textField2.delete(false);
                            } else {
                                if (backspace && TextField.this.cursor > 0) {
                                    TextField textField3 = TextField.this;
                                    StringBuilder sb = new StringBuilder();
                                    sb.append(TextField.this.text.substring(0, TextField.this.cursor - 1));
                                    String str = TextField.this.text;
                                    TextField textField4 = TextField.this;
                                    int i = textField4.cursor;
                                    textField4.cursor = i - 1;
                                    sb.append(str.substring(i));
                                    textField3.text = sb.toString();
                                    TextField.this.renderOffset = 0.0f;
                                }
                                if (delete && TextField.this.cursor < TextField.this.text.length()) {
                                    TextField textField5 = TextField.this;
                                    textField5.text = TextField.this.text.substring(0, TextField.this.cursor) + TextField.this.text.substring(TextField.this.cursor + 1);
                                }
                            }
                        }
                        if (add && !remove) {
                            if (!enter && TextField.this.filter != null && !TextField.this.filter.acceptChar(TextField.this, character)) {
                                return true;
                            }
                            TextField textField6 = TextField.this;
                            if (!textField6.withinMaxLength(textField6.text.length() - (TextField.this.hasSelection ? Math.abs(TextField.this.cursor - TextField.this.selectionStart) : 0))) {
                                return true;
                            }
                            if (TextField.this.hasSelection) {
                                TextField textField7 = TextField.this;
                                textField7.cursor = textField7.delete(false);
                            }
                            String insertion = enter ? "\n" : String.valueOf(character);
                            TextField textField8 = TextField.this;
                            int i2 = textField8.cursor;
                            textField8.cursor = i2 + 1;
                            textField8.text = textField8.insert(i2, insertion, TextField.this.text);
                        }
                        String str2 = TextField.this.undoText;
                        TextField textField9 = TextField.this;
                        if (!textField9.changeText(oldText, textField9.text)) {
                            TextField.this.cursor = oldCursor;
                        } else {
                            long time = System.currentTimeMillis();
                            if (time - 750 > TextField.this.lastChangeTime) {
                                TextField.this.undoText = oldText;
                            }
                            TextField textField10 = TextField.this;
                            textField10.lastChangeTime = time;
                            textField10.updateDisplayText();
                        }
                    }
                }
                if (TextField.this.listener != null) {
                    TextField.this.listener.keyTyped(TextField.this, character);
                    return true;
                }
                return true;
            }
            return false;
        }
    }

    /* loaded from: classes.dex */
    public static class TextFieldStyle {
        public Drawable background;
        public Drawable cursor;
        public Drawable disabledBackground;
        public Color disabledFontColor;
        public Drawable focusedBackground;
        public Color focusedFontColor;
        public BitmapFont font;
        public Color fontColor;
        public BitmapFont messageFont;
        public Color messageFontColor;
        public Drawable selection;

        public TextFieldStyle() {
        }

        public TextFieldStyle(BitmapFont font, Color fontColor, Drawable cursor, Drawable selection, Drawable background) {
            this.font = font;
            this.fontColor = fontColor;
            this.cursor = cursor;
            this.selection = selection;
            this.background = background;
        }

        public TextFieldStyle(TextFieldStyle style) {
            this.font = style.font;
            Color color = style.fontColor;
            if (color != null) {
                this.fontColor = new Color(color);
            }
            Color color2 = style.focusedFontColor;
            if (color2 != null) {
                this.focusedFontColor = new Color(color2);
            }
            Color color3 = style.disabledFontColor;
            if (color3 != null) {
                this.disabledFontColor = new Color(color3);
            }
            this.background = style.background;
            this.focusedBackground = style.focusedBackground;
            this.disabledBackground = style.disabledBackground;
            this.cursor = style.cursor;
            this.selection = style.selection;
            this.messageFont = style.messageFont;
            Color color4 = style.messageFontColor;
            if (color4 != null) {
                this.messageFontColor = new Color(color4);
            }
        }
    }
}