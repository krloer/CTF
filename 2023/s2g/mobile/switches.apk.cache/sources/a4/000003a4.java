package com.badlogic.gdx.scenes.scene2d.ui;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.BitmapFontCache;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.scenes.scene2d.utils.Drawable;
import com.badlogic.gdx.utils.StringBuilder;
import kotlin.jvm.internal.IntCompanionObject;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class Label extends Widget {
    private BitmapFontCache cache;
    private String ellipsis;
    private boolean fontScaleChanged;
    private float fontScaleX;
    private float fontScaleY;
    private int intValue;
    private int labelAlign;
    private float lastPrefHeight;
    private final GlyphLayout layout;
    private int lineAlign;
    private final Vector2 prefSize;
    private boolean prefSizeInvalid;
    private LabelStyle style;
    private final StringBuilder text;
    private boolean wrap;
    private static final Color tempColor = new Color();
    private static final GlyphLayout prefSizeLayout = new GlyphLayout();

    public Label(CharSequence text, Skin skin) {
        this(text, (LabelStyle) skin.get(LabelStyle.class));
    }

    public Label(CharSequence text, Skin skin, String styleName) {
        this(text, (LabelStyle) skin.get(styleName, LabelStyle.class));
    }

    public Label(CharSequence text, Skin skin, String fontName, Color color) {
        this(text, new LabelStyle(skin.getFont(fontName), color));
    }

    public Label(CharSequence text, Skin skin, String fontName, String colorName) {
        this(text, new LabelStyle(skin.getFont(fontName), skin.getColor(colorName)));
    }

    public Label(CharSequence text, LabelStyle style) {
        this.layout = new GlyphLayout();
        this.prefSize = new Vector2();
        this.text = new StringBuilder();
        this.intValue = IntCompanionObject.MIN_VALUE;
        this.labelAlign = 8;
        this.lineAlign = 8;
        this.prefSizeInvalid = true;
        this.fontScaleX = 1.0f;
        this.fontScaleY = 1.0f;
        this.fontScaleChanged = false;
        if (text != null) {
            this.text.append(text);
        }
        setStyle(style);
        if (text == null || text.length() <= 0) {
            return;
        }
        setSize(getPrefWidth(), getPrefHeight());
    }

    public void setStyle(LabelStyle style) {
        if (style == null) {
            throw new IllegalArgumentException("style cannot be null.");
        }
        if (style.font == null) {
            throw new IllegalArgumentException("Missing LabelStyle font.");
        }
        this.style = style;
        this.cache = style.font.newFontCache();
        invalidateHierarchy();
    }

    public LabelStyle getStyle() {
        return this.style;
    }

    public boolean setText(int value) {
        if (this.intValue == value) {
            return false;
        }
        this.text.clear();
        this.text.append(value);
        this.intValue = value;
        invalidateHierarchy();
        return true;
    }

    public void setText(CharSequence newText) {
        if (newText == null) {
            if (this.text.length == 0) {
                return;
            }
            this.text.clear();
        } else if (newText instanceof StringBuilder) {
            if (this.text.equals(newText)) {
                return;
            }
            this.text.clear();
            this.text.append((StringBuilder) newText);
        } else if (textEquals(newText)) {
            return;
        } else {
            this.text.clear();
            this.text.append(newText);
        }
        this.intValue = IntCompanionObject.MIN_VALUE;
        invalidateHierarchy();
    }

    public boolean textEquals(CharSequence other) {
        int length = this.text.length;
        char[] chars = this.text.chars;
        if (length != other.length()) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (chars[i] != other.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    public StringBuilder getText() {
        return this.text;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void invalidate() {
        super.invalidate();
        this.prefSizeInvalid = true;
    }

    private void scaleAndComputePrefSize() {
        BitmapFont font = this.cache.getFont();
        float oldScaleX = font.getScaleX();
        float oldScaleY = font.getScaleY();
        if (this.fontScaleChanged) {
            font.getData().setScale(this.fontScaleX, this.fontScaleY);
        }
        computePrefSize();
        if (this.fontScaleChanged) {
            font.getData().setScale(oldScaleX, oldScaleY);
        }
    }

    private void computePrefSize() {
        float width;
        this.prefSizeInvalid = false;
        GlyphLayout prefSizeLayout2 = prefSizeLayout;
        if (this.wrap && this.ellipsis == null) {
            float width2 = getWidth();
            if (this.style.background == null) {
                width = width2;
            } else {
                width = (Math.max(width2, this.style.background.getMinWidth()) - this.style.background.getLeftWidth()) - this.style.background.getRightWidth();
            }
            prefSizeLayout2.setText(this.cache.getFont(), this.text, Color.WHITE, width, 8, true);
        } else {
            prefSizeLayout2.setText(this.cache.getFont(), this.text);
        }
        this.prefSize.set(prefSizeLayout2.width, prefSizeLayout2.height);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public void layout() {
        float width;
        float height;
        float x;
        float y;
        GlyphLayout layout;
        float textWidth;
        float x2;
        float x3;
        float y2;
        BitmapFont font = this.cache.getFont();
        float oldScaleX = font.getScaleX();
        float oldScaleY = font.getScaleY();
        if (this.fontScaleChanged) {
            font.getData().setScale(this.fontScaleX, this.fontScaleY);
        }
        boolean wrap = this.wrap && this.ellipsis == null;
        if (wrap) {
            float prefHeight = getPrefHeight();
            if (prefHeight != this.lastPrefHeight) {
                this.lastPrefHeight = prefHeight;
                invalidateHierarchy();
            }
        }
        float width2 = getWidth();
        float height2 = getHeight();
        Drawable background = this.style.background;
        if (background == null) {
            width = width2;
            height = height2;
            x = 0.0f;
            y = 0.0f;
        } else {
            float x4 = background.getLeftWidth();
            float y3 = background.getBottomHeight();
            width = width2 - (background.getLeftWidth() + background.getRightWidth());
            height = height2 - (background.getBottomHeight() + background.getTopHeight());
            x = x4;
            y = y3;
        }
        GlyphLayout layout2 = this.layout;
        if (wrap || this.text.indexOf("\n") != -1) {
            StringBuilder stringBuilder = this.text;
            layout = layout2;
            layout2.setText(font, stringBuilder, 0, stringBuilder.length, Color.WHITE, width, this.lineAlign, wrap, this.ellipsis);
            float textWidth2 = layout.width;
            float textHeight = layout.height;
            int i = this.labelAlign;
            if ((i & 8) != 0) {
                textWidth = textWidth2;
                x2 = x;
                x3 = textHeight;
            } else if ((i & 16) == 0) {
                textWidth = textWidth2;
                x2 = x + ((width - textWidth2) / 2.0f);
                x3 = textHeight;
            } else {
                textWidth = textWidth2;
                x2 = x + (width - textWidth2);
                x3 = textHeight;
            }
        } else {
            textWidth = width;
            layout = layout2;
            x2 = x;
            x3 = font.getData().capHeight;
        }
        int i2 = this.labelAlign;
        if ((i2 & 2) != 0) {
            y2 = y + (this.cache.getFont().isFlipped() ? 0.0f : height - x3) + this.style.font.getDescent();
        } else if ((i2 & 4) == 0) {
            y2 = y + ((height - x3) / 2.0f);
        } else {
            y2 = (y + (this.cache.getFont().isFlipped() ? height - x3 : 0.0f)) - this.style.font.getDescent();
        }
        if (!this.cache.getFont().isFlipped()) {
            y2 += x3;
        }
        StringBuilder stringBuilder2 = this.text;
        layout.setText(font, stringBuilder2, 0, stringBuilder2.length, Color.WHITE, textWidth, this.lineAlign, wrap, this.ellipsis);
        this.cache.setText(layout, x2, y2);
        if (this.fontScaleChanged) {
            font.getData().setScale(oldScaleX, oldScaleY);
        }
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.Actor
    public void draw(Batch batch, float parentAlpha) {
        validate();
        Color color = tempColor.set(getColor());
        color.a *= parentAlpha;
        if (this.style.background != null) {
            batch.setColor(color.r, color.g, color.b, color.a);
            this.style.background.draw(batch, getX(), getY(), getWidth(), getHeight());
        }
        if (this.style.fontColor != null) {
            color.mul(this.style.fontColor);
        }
        this.cache.tint(color);
        this.cache.setPosition(getX(), getY());
        this.cache.draw(batch);
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefWidth() {
        if (this.wrap) {
            return 0.0f;
        }
        if (this.prefSizeInvalid) {
            scaleAndComputePrefSize();
        }
        float width = this.prefSize.x;
        Drawable background = this.style.background;
        if (background != null) {
            return Math.max(background.getLeftWidth() + width + background.getRightWidth(), background.getMinWidth());
        }
        return width;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.ui.Widget, com.badlogic.gdx.scenes.scene2d.utils.Layout
    public float getPrefHeight() {
        if (this.prefSizeInvalid) {
            scaleAndComputePrefSize();
        }
        float descentScaleCorrection = this.fontScaleChanged ? this.fontScaleY / this.style.font.getScaleY() : 1.0f;
        float height = this.prefSize.y - ((this.style.font.getDescent() * descentScaleCorrection) * 2.0f);
        Drawable background = this.style.background;
        if (background != null) {
            return Math.max(background.getTopHeight() + height + background.getBottomHeight(), background.getMinHeight());
        }
        return height;
    }

    public GlyphLayout getGlyphLayout() {
        return this.layout;
    }

    public void setWrap(boolean wrap) {
        this.wrap = wrap;
        invalidateHierarchy();
    }

    public boolean getWrap() {
        return this.wrap;
    }

    public int getLabelAlign() {
        return this.labelAlign;
    }

    public int getLineAlign() {
        return this.lineAlign;
    }

    public void setAlignment(int alignment) {
        setAlignment(alignment, alignment);
    }

    public void setAlignment(int labelAlign, int lineAlign) {
        this.labelAlign = labelAlign;
        if ((lineAlign & 8) != 0) {
            this.lineAlign = 8;
        } else if ((lineAlign & 16) != 0) {
            this.lineAlign = 16;
        } else {
            this.lineAlign = 1;
        }
        invalidate();
    }

    public void setFontScale(float fontScale) {
        setFontScale(fontScale, fontScale);
    }

    public void setFontScale(float fontScaleX, float fontScaleY) {
        this.fontScaleChanged = true;
        this.fontScaleX = fontScaleX;
        this.fontScaleY = fontScaleY;
        invalidateHierarchy();
    }

    public float getFontScaleX() {
        return this.fontScaleX;
    }

    public void setFontScaleX(float fontScaleX) {
        setFontScale(fontScaleX, this.fontScaleY);
    }

    public float getFontScaleY() {
        return this.fontScaleY;
    }

    public void setFontScaleY(float fontScaleY) {
        setFontScale(this.fontScaleX, fontScaleY);
    }

    public void setEllipsis(String ellipsis) {
        this.ellipsis = ellipsis;
    }

    public void setEllipsis(boolean ellipsis) {
        if (ellipsis) {
            this.ellipsis = "...";
        } else {
            this.ellipsis = null;
        }
    }

    protected BitmapFontCache getBitmapFontCache() {
        return this.cache;
    }

    @Override // com.badlogic.gdx.scenes.scene2d.Actor
    public String toString() {
        String name = getName();
        if (name != null) {
            return name;
        }
        String className = getClass().getName();
        int dotIndex = className.lastIndexOf(46);
        if (dotIndex != -1) {
            className = className.substring(dotIndex + 1);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(className.indexOf(36) != -1 ? "Label " : BuildConfig.FLAVOR);
        sb.append(className);
        sb.append(": ");
        sb.append((Object) this.text);
        return sb.toString();
    }

    /* loaded from: classes.dex */
    public static class LabelStyle {
        public Drawable background;
        public BitmapFont font;
        public Color fontColor;

        public LabelStyle() {
        }

        public LabelStyle(BitmapFont font, Color fontColor) {
            this.font = font;
            this.fontColor = fontColor;
        }

        public LabelStyle(LabelStyle style) {
            this.font = style.font;
            Color color = style.fontColor;
            if (color != null) {
                this.fontColor = new Color(color);
            }
            this.background = style.background;
        }
    }
}