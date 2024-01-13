package com.kotcrab.vis.ui.widget;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Cursor;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.Actor;
import com.badlogic.gdx.scenes.scene2d.Group;
import com.badlogic.gdx.scenes.scene2d.InputEvent;
import com.badlogic.gdx.scenes.scene2d.InputListener;
import com.badlogic.gdx.scenes.scene2d.Stage;
import com.badlogic.gdx.scenes.scene2d.ui.TextField;
import com.badlogic.gdx.scenes.scene2d.ui.Widget;
import com.badlogic.gdx.scenes.scene2d.ui.Window;
import com.badlogic.gdx.scenes.scene2d.utils.ChangeListener;
import com.badlogic.gdx.scenes.scene2d.utils.ClickListener;
import com.badlogic.gdx.scenes.scene2d.utils.Disableable;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.scenes.scene2d.utils.UIUtils;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Clipboard;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.Pools;
import com.badlogic.gdx.utils.TimeUtils;
import com.badlogic.gdx.utils.Timer;
import com.kotcrab.vis.ui.FocusManager;
import com.kotcrab.vis.ui.Focusable;
import com.kotcrab.vis.ui.VisUI;
import com.kotcrab.vis.ui.util.BorderOwner;
import com.kotcrab.vis.ui.util.CursorManager;
import java.util.Iterator;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class VisTextField extends Widget implements Disableable, Focusable, BorderOwner {
    private static final char BACKSPACE = '\b';
    private static final char BULLET = 8226;
    private static final char DELETE = 127;
    protected static final char ENTER_ANDROID = '\n';
    protected static final char ENTER_DESKTOP = '\r';
    private static final char TAB = '\t';
    private float blinkTime;
    private ClickListener clickListener;
    Clipboard clipboard;
    protected int cursor;
    boolean cursorOn;
    private float cursorPercentHeight;
    boolean disabled;
    protected CharSequence displayText;
    private boolean drawBorder;
    boolean enterKeyFocusTraversal;
    TextFieldFilter filter;
    private boolean focusBorderEnabled;
    boolean focusTraversal;
    protected float fontOffset;
    protected final FloatArray glyphPositions;
    protected boolean hasSelection;
    private boolean ignoreEqualsTextChange;
    InputListener inputListener;
    private boolean inputValid;
    KeyRepeatTask keyRepeatTask;
    TextField.OnscreenKeyboard keyboard;
    long lastBlink;
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
    private boolean readOnly;
    float renderOffset;
    protected int selectionStart;
    private float selectionWidth;
    private float selectionX;
    VisTextFieldStyle style;
    protected String text;
    private int textHAlign;
    protected float textHeight;
    protected float textOffset;
    int undoCursorPos;
    String undoText;
    private int visibleTextEnd;
    private int visibleTextStart;
    protected boolean writeEnters;
    private static final Vector2 tmp1 = new Vector2();
    private static final Vector2 tmp2 = new Vector2();
    private static final Vector2 tmp3 = new Vector2();
    public static float keyRepeatInitialTime = 0.4f;
    public static float keyRepeatTime = 0.04f;

    /* loaded from: classes.dex */
    public interface TextFieldListener {
        void keyTyped(VisTextField visTextField, char c);
    }

    public VisTextField() {
        this(BuildConfig.FLAVOR, (VisTextFieldStyle) VisUI.getSkin().get(VisTextFieldStyle.class));
    }

    public VisTextField(String text) {
        this(text, (VisTextFieldStyle) VisUI.getSkin().get(VisTextFieldStyle.class));
    }

    public VisTextField(String text, String styleName) {
        this(text, (VisTextFieldStyle) VisUI.getSkin().get(styleName, VisTextFieldStyle.class));
    }

    public VisTextField(String text, VisTextFieldStyle style) {
        this.layout = new GlyphLayout();
        this.glyphPositions = new FloatArray();
        this.keyboard = new TextField.DefaultOnscreenKeyboard();
        this.focusTraversal = true;
        this.onlyFontChars = true;
        this.enterKeyFocusTraversal = false;
        this.textHAlign = 8;
        this.undoText = BuildConfig.FLAVOR;
        this.undoCursorPos = 0;
        this.passwordCharacter = (char) 8226;
        this.maxLength = 0;
        this.blinkTime = 0.45f;
        this.cursorOn = true;
        this.keyRepeatTask = new KeyRepeatTask();
        this.focusBorderEnabled = true;
        this.inputValid = true;
        this.ignoreEqualsTextChange = true;
        this.readOnly = false;
        this.cursorPercentHeight = 0.8f;
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
        ClickListener clickListener = new ClickListener() { // from class: com.kotcrab.vis.ui.widget.VisTextField.1
            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void enter(InputEvent event, float x, float y, int pointer, Actor fromActor) {
                super.enter(event, x, y, pointer, fromActor);
                if (pointer == -1 && !VisTextField.this.isDisabled()) {
                    Gdx.graphics.setSystemCursor(Cursor.SystemCursor.Ibeam);
                }
            }

            @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
            public void exit(InputEvent event, float x, float y, int pointer, Actor toActor) {
                super.exit(event, x, y, pointer, toActor);
                if (pointer == -1) {
                    CursorManager.restoreDefaultCursor();
                }
            }
        };
        this.clickListener = clickListener;
        addListener(clickListener);
    }

    protected InputListener createInputListener() {
        return new TextFieldClickListener();
    }

    protected int letterUnderCursor(float x) {
        float x2 = x - (((this.textOffset + this.fontOffset) - this.style.font.getData().cursorX) - this.glyphPositions.get(this.visibleTextStart));
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
        int start = Math.min(text.length(), at);
        int right = text.length();
        int left = 0;
        int index = start;
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
        int index2 = start - 1;
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
        return new int[]{left, right};
    }

    int[] wordUnderCursor(float x) {
        return wordUnderCursor(letterUnderCursor(x));
    }

    boolean withinMaxLength(int size) {
        int i = this.maxLength;
        return i <= 0 || size < i;
    }

    public int getMaxLength() {
        return this.maxLength;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public void setOnlyFontChars(boolean onlyFontChars) {
        this.onlyFontChars = onlyFontChars;
    }

    public VisTextFieldStyle getStyle() {
        return this.style;
    }

    public void setStyle(VisTextFieldStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        this.style = style;
        this.textHeight = style.font.getCapHeight() - (style.font.getDescent() * 2.0f);
        invalidateHierarchy();
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public String toString() {
        return getText();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void calculateOffsets() {
        float visibleWidth = getWidth();
        if (this.style.background != null) {
            visibleWidth -= this.style.background.getLeftWidth() + this.style.background.getRightWidth();
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
                    this.visibleTextStart = Math.max(0, i2);
                    startX = glyphPositions[i2];
                    break;
                }
            } else {
                break;
            }
        }
        int length = Math.min(this.displayText.length(), glyphPositions.length - 1);
        this.visibleTextEnd = Math.min(length, this.cursor + 1);
        while (true) {
            int i3 = this.visibleTextEnd;
            if (i3 > length || glyphPositions[i3] > startX + visibleWidth) {
                break;
            }
            this.visibleTextEnd = i3 + 1;
        }
        this.visibleTextEnd = Math.max(0, this.visibleTextEnd - 1);
        int i4 = this.textHAlign;
        if ((i4 & 8) == 0) {
            this.textOffset = visibleWidth - (glyphPositions[this.visibleTextEnd] - startX);
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

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        Drawable background;
        float bgLeftWidth;
        float bgRightWidth;
        Drawable cursorPatch;
        Color fontColor;
        BitmapFont font;
        Stage stage = getStage();
        boolean focused = stage != null && stage.getKeyboardFocus() == this;
        if (!focused) {
            this.keyRepeatTask.cancel();
        }
        BitmapFont font2 = this.style.font;
        Color fontColor2 = (!this.disabled || this.style.disabledFontColor == null) ? (!focused || this.style.focusedFontColor == null) ? this.style.fontColor : this.style.focusedFontColor : this.style.disabledFontColor;
        Drawable selection = this.style.selection;
        Drawable cursorPatch2 = this.style.cursor;
        Drawable background2 = (!this.disabled || this.style.disabledBackground == null) ? (!focused || this.style.focusedBackground == null) ? this.style.background : this.style.focusedBackground : this.style.disabledBackground;
        if (!this.disabled && this.clickListener.isOver() && this.style.backgroundOver != null) {
            Drawable background3 = this.style.backgroundOver;
            background = background3;
        } else {
            background = background2;
        }
        Color color = getColor();
        float x = getX();
        float y = getY();
        float width = getWidth();
        float height = getHeight();
        batch.setColor(color.r, color.g, color.b, color.a * parentAlpha);
        if (background == null) {
            bgLeftWidth = 0.0f;
            bgRightWidth = 0.0f;
        } else {
            background.draw(batch, x, y, width, height);
            float bgLeftWidth2 = background.getLeftWidth();
            float bgRightWidth2 = background.getRightWidth();
            bgLeftWidth = bgLeftWidth2;
            bgRightWidth = bgRightWidth2;
        }
        float textY = getTextY(font2, background);
        calculateOffsets();
        if (focused && this.hasSelection && selection != null) {
            drawSelection(selection, batch, font2, x + bgLeftWidth, y + textY);
        }
        float yOffset = font2.isFlipped() ? -this.textHeight : 0.0f;
        if (this.displayText.length() == 0) {
            if (focused || this.messageText == null) {
                cursorPatch = cursorPatch2;
                fontColor = fontColor2;
                font = font2;
            } else {
                if (this.style.messageFontColor != null) {
                    font2.setColor(this.style.messageFontColor.r, this.style.messageFontColor.g, this.style.messageFontColor.b, this.style.messageFontColor.a * color.a * parentAlpha);
                } else {
                    font2.setColor(0.7f, 0.7f, 0.7f, color.a * parentAlpha);
                }
                BitmapFont messageFont = this.style.messageFont != null ? this.style.messageFont : font2;
                String str = this.messageText;
                cursorPatch = cursorPatch2;
                fontColor = fontColor2;
                font = font2;
                messageFont.draw(batch, str, x + bgLeftWidth, y + textY + yOffset, 0, str.length(), (width - bgLeftWidth) - bgRightWidth, this.textHAlign, false, "...");
            }
        } else {
            cursorPatch = cursorPatch2;
            fontColor = fontColor2;
            font = font2;
            font.setColor(fontColor.r, fontColor.g, fontColor.b, fontColor.a * color.a * parentAlpha);
            drawText(batch, font, x + bgLeftWidth, y + textY + yOffset);
        }
        if (this.drawBorder && focused && !this.disabled) {
            blink();
            if (this.cursorOn && cursorPatch != null) {
                drawCursor(cursorPatch, batch, font, x + bgLeftWidth, y + textY);
            }
        }
        if (!isDisabled() && !this.inputValid && this.style.errorBorder != null) {
            this.style.errorBorder.draw(batch, getX(), getY(), getWidth(), getHeight());
        } else if (this.focusBorderEnabled && this.drawBorder && this.style.focusBorder != null) {
            this.style.focusBorder.draw(batch, getX(), getY(), getWidth(), getHeight());
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
        selection.draw(batch, this.selectionX + x + this.textOffset + this.fontOffset, (y - this.textHeight) - font.getDescent(), this.selectionWidth, this.textHeight);
    }

    protected void drawText(Batch batch, BitmapFont font, float x, float y) {
        font.draw(batch, this.displayText, x + this.textOffset, y, this.visibleTextStart, this.visibleTextEnd, 0.0f, 8, false);
    }

    protected void drawCursor(Drawable cursorPatch, Batch batch, BitmapFont font, float x, float y) {
        float f = this.textHeight;
        float cursorHeight = this.cursorPercentHeight * f;
        float cursorYPadding = (f - cursorHeight) / 2.0f;
        cursorPatch.draw(batch, (((this.textOffset + x) + this.glyphPositions.get(this.cursor)) - this.glyphPositions.get(this.visibleTextStart)) + this.fontOffset + font.getData().cursorX, ((y - this.textHeight) - font.getDescent()) + cursorYPadding, cursorPatch.getMinWidth(), cursorHeight);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateDisplayText() {
        BitmapFont font = this.style.font;
        BitmapFont.BitmapFontData data = font.getData();
        String text = this.text;
        int textLength = text.length();
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < textLength; i++) {
            char c = text.charAt(i);
            buffer.append(data.hasGlyph(c) ? c : ' ');
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
        this.layout.setText(font, this.displayText);
        this.glyphPositions.clear();
        float x = 0.0f;
        if (this.layout.runs.size > 0) {
            GlyphLayout.GlyphRun run = this.layout.runs.first();
            this.fontOffset = run.xAdvances.first();
            Iterator it = this.layout.runs.iterator();
            while (it.hasNext()) {
                GlyphLayout.GlyphRun glyphRun = (GlyphLayout.GlyphRun) it.next();
                FloatArray xAdvances = glyphRun.xAdvances;
                int n = xAdvances.size;
                for (int i3 = 1; i3 < n; i3++) {
                    this.glyphPositions.add(x);
                    x += xAdvances.get(i3);
                }
                this.glyphPositions.add(x);
            }
        } else {
            this.fontOffset = 0.0f;
        }
        this.glyphPositions.add(x);
        if (this.selectionStart > newDisplayText.length()) {
            this.selectionStart = textLength;
        }
    }

    private void blink() {
        if (!Gdx.graphics.isContinuousRendering()) {
            this.cursorOn = true;
            return;
        }
        long time = TimeUtils.nanoTime();
        if (((float) (time - this.lastBlink)) / 1.0E9f > this.blinkTime) {
            this.cursorOn = !this.cursorOn;
            this.lastBlink = time;
        }
    }

    public void copy() {
        if (this.hasSelection && !this.passwordMode) {
            int beginIndex = Math.min(this.cursor, this.selectionStart);
            int endIndex = Math.max(this.cursor, this.selectionStart);
            this.clipboard.setContents(this.text.substring(Math.max(0, beginIndex), Math.min(this.text.length(), endIndex)));
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
        getParent().localToStageCoordinates(tmp1.set(getX(), getY()));
        VisTextField textField = findNextTextField(stage.getActors(), null, tmp2, tmp1, up);
        if (textField == null) {
            if (up) {
                tmp1.set(Float.MIN_VALUE, Float.MIN_VALUE);
            } else {
                tmp1.set(Float.MAX_VALUE, Float.MAX_VALUE);
            }
            textField = findNextTextField(getStage().getActors(), null, tmp2, tmp1, up);
        }
        if (textField != null) {
            textField.focusField();
            textField.setCursorPosition(textField.getText().length());
            return;
        }
        Gdx.input.setOnscreenKeyboardVisible(false);
    }

    private VisTextField findNextTextField(Array<Actor> actors, VisTextField best, Vector2 bestCoords, Vector2 currentCoords, boolean up) {
        Window modalWindow = findModalWindow(this);
        int n = actors.size;
        for (int i = 0; i < n; i++) {
            Actor actor = actors.get(i);
            if (actor != this) {
                if (actor instanceof VisTextField) {
                    VisTextField textField = (VisTextField) actor;
                    if (modalWindow != null) {
                        Window nextFieldModalWindow = findModalWindow(textField);
                        if (nextFieldModalWindow != modalWindow) {
                        }
                    }
                    if (!textField.isDisabled() && textField.focusTraversal && isActorVisibleInStage(textField)) {
                        Vector2 actorCoords = actor.getParent().localToStageCoordinates(tmp3.set(actor.getX(), actor.getY()));
                        boolean z = false;
                        if ((actorCoords.y < currentCoords.y || (actorCoords.y == currentCoords.y && actorCoords.x > currentCoords.x)) ^ up) {
                            if (best != null) {
                                if (actorCoords.y > bestCoords.y || (actorCoords.y == bestCoords.y && actorCoords.x < bestCoords.x)) {
                                    z = true;
                                }
                                if (!(z ^ up)) {
                                }
                            }
                            best = (VisTextField) actor;
                            bestCoords.set(actorCoords);
                        }
                    }
                } else if (actor instanceof Group) {
                    best = findNextTextField(((Group) actor).getChildren(), best, bestCoords, currentCoords, up);
                }
            }
        }
        return best;
    }

    private boolean isActorVisibleInStage(Actor actor) {
        if (actor == null) {
            return true;
        }
        if (actor.isVisible()) {
            return isActorVisibleInStage(actor.getParent());
        }
        return false;
    }

    private Window findModalWindow(Actor actor) {
        if (actor == null) {
            return null;
        }
        return ((actor instanceof Window) && ((Window) actor).isModal()) ? (Window) actor : findModalWindow(actor.getParent());
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

    public void setEnterKeyFocusTraversal(boolean enterKeyFocusTraversal) {
        this.enterKeyFocusTraversal = enterKeyFocusTraversal;
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
        if (this.ignoreEqualsTextChange && str.equals(this.text)) {
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

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean changeText(String oldText, String newText) {
        if (this.ignoreEqualsTextChange && newText.equals(oldText)) {
            return false;
        }
        this.text = newText;
        beforeChangeEventFired();
        ChangeListener.ChangeEvent changeEvent = (ChangeListener.ChangeEvent) Pools.obtain(ChangeListener.ChangeEvent.class);
        boolean cancelled = fire(changeEvent);
        this.text = cancelled ? oldText : newText;
        Pools.free(changeEvent);
        return !cancelled;
    }

    void beforeChangeEventFired() {
    }

    public boolean getProgrammaticChangeEvents() {
        return this.programmaticChangeEvents;
    }

    public void setProgrammaticChangeEvents(boolean programmaticChangeEvents) {
        this.programmaticChangeEvents = programmaticChangeEvents;
    }

    public int getSelectionStart() {
        return this.selectionStart;
    }

    public String getSelection() {
        return this.hasSelection ? this.text.substring(Math.min(this.selectionStart, this.cursor), Math.max(this.selectionStart, this.cursor)) : BuildConfig.FLAVOR;
    }

    public boolean isTextSelected() {
        return this.hasSelection;
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

    public void clearText() {
        setText(BuildConfig.FLAVOR);
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

    public void setCursorAtTextEnd() {
        setCursorPosition(0);
        calculateOffsets();
        setCursorPosition(getText().length());
    }

    public void setCursorPercentHeight(float cursorPercentHeight) {
        if (cursorPercentHeight < 0.0f || cursorPercentHeight > 1.0f) {
            throw new IllegalArgumentException("cursorPercentHeight must be >= 0 and <= 1");
        }
        this.cursorPercentHeight = cursorPercentHeight;
    }

    public TextField.OnscreenKeyboard getOnscreenKeyboard() {
        return this.keyboard;
    }

    public void setOnscreenKeyboard(TextField.OnscreenKeyboard keyboard) {
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
        float prefHeight = this.textHeight;
        if (this.style.background != null) {
            return Math.max(this.style.background.getBottomHeight() + prefHeight + this.style.background.getTopHeight(), this.style.background.getMinHeight());
        }
        return prefHeight;
    }

    public void setAlignment(int alignment) {
        this.textHAlign = alignment;
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
    public boolean isDisabled() {
        return this.disabled;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.utils.Disableable
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
        if (disabled) {
            FocusManager.resetFocus(getStage(), this);
            this.keyRepeatTask.cancel();
        }
    }

    public boolean isReadOnly() {
        return this.readOnly;
    }

    public void setReadOnly(boolean readOnly) {
        this.readOnly = readOnly;
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

    public void focusField() {
        if (this.disabled) {
            return;
        }
        Stage stage = getStage();
        FocusManager.switchFocus(stage, this);
        setCursorPosition(0);
        this.selectionStart = 0;
        calculateOffsets();
        if (stage != null) {
            stage.setKeyboardFocus(this);
        }
        this.keyboard.show(true);
        this.hasSelection = true;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusLost() {
        this.drawBorder = false;
    }

    @Override // com.kotcrab.vis.ui.Focusable
    public void focusGained() {
        this.drawBorder = true;
    }

    public boolean isEmpty() {
        return this.text.length() == 0;
    }

    public boolean isInputValid() {
        return this.inputValid;
    }

    public void setInputValid(boolean inputValid) {
        this.inputValid = inputValid;
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public boolean isFocusBorderEnabled() {
        return this.focusBorderEnabled;
    }

    @Override // com.kotcrab.vis.ui.util.BorderOwner
    public void setFocusBorderEnabled(boolean focusBorderEnabled) {
        this.focusBorderEnabled = focusBorderEnabled;
    }

    public boolean isIgnoreEqualsTextChange() {
        return this.ignoreEqualsTextChange;
    }

    public void setIgnoreEqualsTextChange(boolean ignoreEqualsTextChange) {
        this.ignoreEqualsTextChange = ignoreEqualsTextChange;
    }

    /* loaded from: classes.dex */
    public static class VisTextFieldStyle extends TextField.TextFieldStyle {
        public Drawable backgroundOver;
        public Drawable errorBorder;
        public Drawable focusBorder;

        public VisTextFieldStyle() {
        }

        public VisTextFieldStyle(BitmapFont font, Color fontColor, Drawable cursor, Drawable selection, Drawable background) {
            super(font, fontColor, cursor, selection, background);
        }

        public VisTextFieldStyle(VisTextFieldStyle style) {
            super(style);
            this.focusBorder = style.focusBorder;
            this.errorBorder = style.errorBorder;
            this.backgroundOver = style.backgroundOver;
        }
    }

    /* loaded from: classes.dex */
    public interface TextFieldFilter {
        boolean acceptChar(VisTextField visTextField, char c);

        /* loaded from: classes.dex */
        public static class DigitsOnlyFilter implements TextFieldFilter {
            @Override // com.kotcrab.vis.ui.widget.VisTextField.TextFieldFilter
            public boolean acceptChar(VisTextField textField, char c) {
                return Character.isDigit(c);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class KeyRepeatTask extends Timer.Task {
        int keycode;

        KeyRepeatTask() {
        }

        @Override // com.badlogic.gdx.utils.Timer.Task, java.lang.Runnable
        public void run() {
            VisTextField.this.inputListener.keyDown(null, this.keycode);
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
                VisTextField.this.clearSelection();
            }
            if (count == 2) {
                int[] array = VisTextField.this.wordUnderCursor(x);
                VisTextField.this.setSelection(array[0], array[1]);
            }
            if (count == 3) {
                VisTextField.this.selectAll();
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.utils.ClickListener, com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean touchDown(InputEvent event, float x, float y, int pointer, int button) {
            if (super.touchDown(event, x, y, pointer, button)) {
                if (pointer != 0 || button == 0) {
                    if (VisTextField.this.disabled) {
                        return true;
                    }
                    Stage stage = VisTextField.this.getStage();
                    FocusManager.switchFocus(stage, VisTextField.this);
                    setCursorPosition(x, y);
                    VisTextField visTextField = VisTextField.this;
                    visTextField.selectionStart = visTextField.cursor;
                    if (stage != null) {
                        stage.setKeyboardFocus(VisTextField.this);
                    }
                    if (!VisTextField.this.readOnly) {
                        VisTextField.this.keyboard.show(true);
                    }
                    VisTextField.this.hasSelection = true;
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
            if (VisTextField.this.selectionStart == VisTextField.this.cursor) {
                VisTextField.this.hasSelection = false;
            }
            super.touchUp(event, x, y, pointer, button);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public void setCursorPosition(float x, float y) {
            VisTextField visTextField = VisTextField.this;
            visTextField.lastBlink = 0L;
            visTextField.cursorOn = false;
            visTextField.cursor = Math.min(visTextField.letterUnderCursor(x), VisTextField.this.text.length());
        }

        protected void goHome(boolean jump) {
            VisTextField.this.cursor = 0;
        }

        protected void goEnd(boolean jump) {
            VisTextField visTextField = VisTextField.this;
            visTextField.cursor = visTextField.text.length();
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyDown(InputEvent event, int keycode) {
            if (VisTextField.this.disabled) {
                return false;
            }
            VisTextField visTextField = VisTextField.this;
            visTextField.lastBlink = 0L;
            visTextField.cursorOn = false;
            Stage stage = visTextField.getStage();
            if (stage != null) {
                Actor keyboardFocus = stage.getKeyboardFocus();
                VisTextField visTextField2 = VisTextField.this;
                if (keyboardFocus == visTextField2 && visTextField2.drawBorder) {
                    boolean repeat = false;
                    boolean ctrl = UIUtils.ctrl();
                    boolean jump = ctrl && !VisTextField.this.passwordMode;
                    if (ctrl) {
                        if (keycode == 50 && !VisTextField.this.readOnly) {
                            VisTextField visTextField3 = VisTextField.this;
                            visTextField3.paste(visTextField3.clipboard.getContents(), true);
                            repeat = true;
                        }
                        if (keycode == 31 || keycode == 133) {
                            VisTextField.this.copy();
                            return true;
                        } else if (keycode == 52 && !VisTextField.this.readOnly) {
                            VisTextField.this.cut(true);
                            return true;
                        } else if (keycode == 29) {
                            VisTextField.this.selectAll();
                            return true;
                        } else if (keycode == 54 && !VisTextField.this.readOnly) {
                            String oldText = VisTextField.this.text;
                            int oldCursorPos = VisTextField.this.getCursorPosition();
                            VisTextField visTextField4 = VisTextField.this;
                            visTextField4.setText(visTextField4.undoText);
                            VisTextField visTextField5 = VisTextField.this;
                            visTextField5.setCursorPosition(visTextField5.undoCursorPos);
                            VisTextField visTextField6 = VisTextField.this;
                            visTextField6.undoText = oldText;
                            visTextField6.undoCursorPos = oldCursorPos;
                            visTextField6.updateDisplayText();
                            return true;
                        }
                    }
                    if (UIUtils.shift()) {
                        if (keycode == 133 && !VisTextField.this.readOnly) {
                            VisTextField visTextField7 = VisTextField.this;
                            visTextField7.paste(visTextField7.clipboard.getContents(), true);
                        }
                        if (keycode == 112 && !VisTextField.this.readOnly) {
                            VisTextField.this.cut(true);
                        }
                        int temp = VisTextField.this.cursor;
                        if (keycode == 21) {
                            VisTextField.this.moveCursor(false, jump);
                            repeat = true;
                        } else if (keycode == 22) {
                            VisTextField.this.moveCursor(true, jump);
                            repeat = true;
                        } else if (keycode == 3) {
                            goHome(jump);
                        } else if (keycode == 132) {
                            goEnd(jump);
                        }
                        if (!VisTextField.this.hasSelection) {
                            VisTextField visTextField8 = VisTextField.this;
                            visTextField8.selectionStart = temp;
                            visTextField8.hasSelection = true;
                        }
                    } else {
                        if (keycode == 21) {
                            VisTextField.this.moveCursor(false, jump);
                            VisTextField.this.clearSelection();
                            repeat = true;
                        }
                        if (keycode == 22) {
                            VisTextField.this.moveCursor(true, jump);
                            VisTextField.this.clearSelection();
                            repeat = true;
                        }
                        if (keycode == 3) {
                            goHome(jump);
                            VisTextField.this.clearSelection();
                        }
                        if (keycode == 132) {
                            goEnd(jump);
                            VisTextField.this.clearSelection();
                        }
                    }
                    VisTextField visTextField9 = VisTextField.this;
                    visTextField9.cursor = MathUtils.clamp(visTextField9.cursor, 0, VisTextField.this.text.length());
                    if (repeat) {
                        scheduleKeyRepeatTask(keycode);
                    }
                    return true;
                }
                return false;
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public void scheduleKeyRepeatTask(int keycode) {
            if (!VisTextField.this.keyRepeatTask.isScheduled() || VisTextField.this.keyRepeatTask.keycode != keycode) {
                VisTextField.this.keyRepeatTask.keycode = keycode;
                VisTextField.this.keyRepeatTask.cancel();
                if (Gdx.input.isKeyPressed(VisTextField.this.keyRepeatTask.keycode)) {
                    Timer.schedule(VisTextField.this.keyRepeatTask, VisTextField.keyRepeatInitialTime, VisTextField.keyRepeatTime);
                }
            }
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyUp(InputEvent event, int keycode) {
            if (VisTextField.this.disabled) {
                return false;
            }
            VisTextField.this.keyRepeatTask.cancel();
            return true;
        }

        @Override // com.badlogic.gdx.scenes.scene2d.InputListener
        public boolean keyTyped(InputEvent event, char character) {
            boolean add;
            if (VisTextField.this.disabled || VisTextField.this.readOnly) {
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
            Stage stage = VisTextField.this.getStage();
            if (stage == null || stage.getKeyboardFocus() != VisTextField.this) {
                return false;
            }
            if (UIUtils.isMac && Gdx.input.isKeyPressed(63)) {
                return true;
            }
            if (VisTextField.this.focusTraversal && (character == '\t' || (character == '\n' && VisTextField.this.enterKeyFocusTraversal))) {
                VisTextField.this.next(UIUtils.shift());
            } else {
                boolean delete = character == 127;
                boolean backspace = character == '\b';
                boolean enter = character == '\r' || character == '\n';
                VisTextField visTextField = VisTextField.this;
                if (enter) {
                    add = visTextField.writeEnters;
                } else {
                    add = !visTextField.onlyFontChars || VisTextField.this.style.font.getData().hasGlyph(character);
                }
                boolean remove = backspace || delete;
                if (add || remove) {
                    String oldText = VisTextField.this.text;
                    int oldCursor = VisTextField.this.cursor;
                    if (VisTextField.this.hasSelection) {
                        VisTextField visTextField2 = VisTextField.this;
                        visTextField2.cursor = visTextField2.delete(false);
                    } else {
                        if (backspace && VisTextField.this.cursor > 0) {
                            VisTextField visTextField3 = VisTextField.this;
                            StringBuilder sb = new StringBuilder();
                            sb.append(VisTextField.this.text.substring(0, VisTextField.this.cursor - 1));
                            String str = VisTextField.this.text;
                            VisTextField visTextField4 = VisTextField.this;
                            int i = visTextField4.cursor;
                            visTextField4.cursor = i - 1;
                            sb.append(str.substring(i));
                            visTextField3.text = sb.toString();
                            VisTextField.this.renderOffset = 0.0f;
                        }
                        if (delete && VisTextField.this.cursor < VisTextField.this.text.length()) {
                            VisTextField visTextField5 = VisTextField.this;
                            visTextField5.text = VisTextField.this.text.substring(0, VisTextField.this.cursor) + VisTextField.this.text.substring(VisTextField.this.cursor + 1);
                        }
                    }
                    if (add && !remove) {
                        if (!enter && VisTextField.this.filter != null && !VisTextField.this.filter.acceptChar(VisTextField.this, character)) {
                            return true;
                        }
                        VisTextField visTextField6 = VisTextField.this;
                        if (!visTextField6.withinMaxLength(visTextField6.text.length())) {
                            return true;
                        }
                        String insertion = enter ? "\n" : String.valueOf(character);
                        VisTextField visTextField7 = VisTextField.this;
                        int i2 = visTextField7.cursor;
                        visTextField7.cursor = i2 + 1;
                        visTextField7.text = visTextField7.insert(i2, insertion, VisTextField.this.text);
                    }
                    VisTextField visTextField8 = VisTextField.this;
                    if (!visTextField8.changeText(oldText, visTextField8.text)) {
                        VisTextField.this.cursor = oldCursor;
                    } else {
                        long time = System.currentTimeMillis();
                        if (time - 750 > VisTextField.this.lastChangeTime) {
                            VisTextField visTextField9 = VisTextField.this;
                            visTextField9.undoText = oldText;
                            visTextField9.undoCursorPos = visTextField9.getCursorPosition() - 1;
                        }
                        VisTextField.this.lastChangeTime = time;
                    }
                    VisTextField.this.updateDisplayText();
                }
            }
            if (VisTextField.this.listener != null) {
                VisTextField.this.listener.keyTyped(VisTextField.this, character);
                return true;
            }
            return true;
        }
    }
}