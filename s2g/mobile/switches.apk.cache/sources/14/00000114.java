package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.NumberUtils;
import com.badlogic.gdx.utils.Pools;

/* loaded from: classes.dex */
public class BitmapFontCache {
    private static final Color tempColor = new Color(1.0f, 1.0f, 1.0f, 1.0f);
    private final Color color;
    private float currentTint;
    private final BitmapFont font;
    private int glyphCount;
    private int[] idx;
    private boolean integer;
    private final Array<GlyphLayout> layouts;
    private IntArray[] pageGlyphIndices;
    private float[][] pageVertices;
    private final Array<GlyphLayout> pooledLayouts;
    private int[] tempGlyphCount;
    private float x;
    private float y;

    public BitmapFontCache(BitmapFont font) {
        this(font, font.usesIntegerPositions());
    }

    public BitmapFontCache(BitmapFont font, boolean integer) {
        this.layouts = new Array<>();
        this.pooledLayouts = new Array<>();
        this.color = new Color(1.0f, 1.0f, 1.0f, 1.0f);
        this.font = font;
        this.integer = integer;
        int pageCount = font.regions.size;
        if (pageCount == 0) {
            throw new IllegalArgumentException("The specified font must contain at least one texture page.");
        }
        this.pageVertices = new float[pageCount];
        this.idx = new int[pageCount];
        if (pageCount > 1) {
            this.pageGlyphIndices = new IntArray[pageCount];
            int n = this.pageGlyphIndices.length;
            for (int i = 0; i < n; i++) {
                this.pageGlyphIndices[i] = new IntArray();
            }
        }
        this.tempGlyphCount = new int[pageCount];
    }

    public void setPosition(float x, float y) {
        translate(x - this.x, y - this.y);
    }

    public void translate(float xAmount, float yAmount) {
        if (xAmount == 0.0f && yAmount == 0.0f) {
            return;
        }
        if (this.integer) {
            xAmount = Math.round(xAmount);
            yAmount = Math.round(yAmount);
        }
        this.x += xAmount;
        this.y += yAmount;
        float[][] pageVertices = this.pageVertices;
        int n = pageVertices.length;
        for (int i = 0; i < n; i++) {
            float[] vertices = pageVertices[i];
            int nn = this.idx[i];
            for (int ii = 0; ii < nn; ii += 5) {
                vertices[ii] = vertices[ii] + xAmount;
                int i2 = ii + 1;
                vertices[i2] = vertices[i2] + yAmount;
            }
        }
    }

    public void tint(Color tint) {
        int[] tempGlyphCount;
        BitmapFontCache bitmapFontCache = this;
        float newTint = tint.toFloatBits();
        if (bitmapFontCache.currentTint == newTint) {
            return;
        }
        bitmapFontCache.currentTint = newTint;
        int[] tempGlyphCount2 = bitmapFontCache.tempGlyphCount;
        int n = tempGlyphCount2.length;
        for (int i = 0; i < n; i++) {
            tempGlyphCount2[i] = 0;
        }
        int i2 = 0;
        int n2 = bitmapFontCache.layouts.size;
        while (i2 < n2) {
            GlyphLayout layout = bitmapFontCache.layouts.get(i2);
            int ii = 0;
            int nn = layout.runs.size;
            while (ii < nn) {
                GlyphLayout.GlyphRun run = layout.runs.get(ii);
                Array<BitmapFont.Glyph> glyphs = run.glyphs;
                float colorFloat = tempColor.set(run.color).mul(tint).toFloatBits();
                int iii = 0;
                int nnn = glyphs.size;
                while (iii < nnn) {
                    BitmapFont.Glyph glyph = glyphs.get(iii);
                    int page = glyph.page;
                    float newTint2 = newTint;
                    int offset = (tempGlyphCount2[page] * 20) + 2;
                    tempGlyphCount2[page] = tempGlyphCount2[page] + 1;
                    float[] vertices = bitmapFontCache.pageVertices[page];
                    int v = 0;
                    while (true) {
                        tempGlyphCount = tempGlyphCount2;
                        if (v < 20) {
                            vertices[offset + v] = colorFloat;
                            v += 5;
                            tempGlyphCount2 = tempGlyphCount;
                        }
                    }
                    iii++;
                    bitmapFontCache = this;
                    newTint = newTint2;
                    tempGlyphCount2 = tempGlyphCount;
                }
                ii++;
                bitmapFontCache = this;
            }
            i2++;
            bitmapFontCache = this;
        }
    }

    public void setAlphas(float alpha) {
        int alphaBits = ((int) (254.0f * alpha)) << 24;
        float prev = 0.0f;
        float newColor = 0.0f;
        int length = this.pageVertices.length;
        for (int j = 0; j < length; j++) {
            float[] vertices = this.pageVertices[j];
            int n = this.idx[j];
            for (int i = 2; i < n; i += 5) {
                float c = vertices[i];
                if (c == prev && i != 2) {
                    vertices[i] = newColor;
                } else {
                    prev = c;
                    int rgba = NumberUtils.floatToIntColor(c);
                    newColor = NumberUtils.intToFloatColor((16777215 & rgba) | alphaBits);
                    vertices[i] = newColor;
                }
            }
        }
    }

    public void setColors(float color) {
        int length = this.pageVertices.length;
        for (int j = 0; j < length; j++) {
            float[] vertices = this.pageVertices[j];
            int n = this.idx[j];
            for (int i = 2; i < n; i += 5) {
                vertices[i] = color;
            }
        }
    }

    public void setColors(Color tint) {
        setColors(tint.toFloatBits());
    }

    public void setColors(float r, float g, float b, float a) {
        int intBits = ((int) (255.0f * r)) | (((int) (a * 255.0f)) << 24) | (((int) (b * 255.0f)) << 16) | (((int) (g * 255.0f)) << 8);
        setColors(NumberUtils.intToFloatColor(intBits));
    }

    public void setColors(Color tint, int start, int end) {
        setColors(tint.toFloatBits(), start, end);
    }

    public void setColors(float color, int start, int end) {
        float[][] fArr = this.pageVertices;
        if (fArr.length == 1) {
            float[] vertices = fArr[0];
            int n = Math.min(end * 20, this.idx[0]);
            for (int i = (start * 20) + 2; i < n; i += 5) {
                vertices[i] = color;
            }
            return;
        }
        int pageCount = fArr.length;
        for (int i2 = 0; i2 < pageCount; i2++) {
            float[] vertices2 = this.pageVertices[i2];
            IntArray glyphIndices = this.pageGlyphIndices[i2];
            int n2 = glyphIndices.size;
            for (int j = 0; j < n2; j++) {
                int glyphIndex = glyphIndices.items[j];
                if (glyphIndex >= end) {
                    break;
                }
                if (glyphIndex >= start) {
                    for (int off = 0; off < 20; off += 5) {
                        vertices2[(j * 20) + 2 + off] = color;
                    }
                }
            }
        }
    }

    public Color getColor() {
        return this.color;
    }

    public void setColor(Color color) {
        this.color.set(color);
    }

    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
    }

    public void draw(Batch spriteBatch) {
        Array<TextureRegion> regions = this.font.getRegions();
        int n = this.pageVertices.length;
        for (int j = 0; j < n; j++) {
            if (this.idx[j] > 0) {
                float[] vertices = this.pageVertices[j];
                spriteBatch.draw(regions.get(j).getTexture(), vertices, 0, this.idx[j]);
            }
        }
    }

    public void draw(Batch spriteBatch, int start, int end) {
        int glyphIndex;
        if (this.pageVertices.length == 1) {
            spriteBatch.draw(this.font.getRegion().getTexture(), this.pageVertices[0], start * 20, (end - start) * 20);
            return;
        }
        Array<TextureRegion> regions = this.font.getRegions();
        int pageCount = this.pageVertices.length;
        for (int i = 0; i < pageCount; i++) {
            int offset = -1;
            int count = 0;
            IntArray glyphIndices = this.pageGlyphIndices[i];
            int n = glyphIndices.size;
            for (int ii = 0; ii < n && (glyphIndex = glyphIndices.get(ii)) < end; ii++) {
                if (offset == -1 && glyphIndex >= start) {
                    offset = ii;
                }
                if (glyphIndex >= start) {
                    count++;
                }
            }
            if (offset != -1 && count != 0) {
                spriteBatch.draw(regions.get(i).getTexture(), this.pageVertices[i], offset * 20, count * 20);
            }
        }
    }

    public void draw(Batch spriteBatch, float alphaModulation) {
        if (alphaModulation == 1.0f) {
            draw(spriteBatch);
            return;
        }
        Color color = getColor();
        float oldAlpha = color.a;
        color.a *= alphaModulation;
        setColors(color);
        draw(spriteBatch);
        color.a = oldAlpha;
        setColors(color);
    }

    public void clear() {
        this.x = 0.0f;
        this.y = 0.0f;
        Pools.freeAll(this.pooledLayouts, true);
        this.pooledLayouts.clear();
        this.layouts.clear();
        int n = this.idx.length;
        for (int i = 0; i < n; i++) {
            IntArray[] intArrayArr = this.pageGlyphIndices;
            if (intArrayArr != null) {
                intArrayArr[i].clear();
            }
            this.idx[i] = 0;
        }
    }

    private void requireGlyphs(GlyphLayout layout) {
        if (this.pageVertices.length == 1) {
            int newGlyphCount = 0;
            int n = layout.runs.size;
            for (int i = 0; i < n; i++) {
                newGlyphCount += layout.runs.get(i).glyphs.size;
            }
            requirePageGlyphs(0, newGlyphCount);
            return;
        }
        int[] tempGlyphCount = this.tempGlyphCount;
        int n2 = tempGlyphCount.length;
        for (int i2 = 0; i2 < n2; i2++) {
            tempGlyphCount[i2] = 0;
        }
        int n3 = layout.runs.size;
        for (int i3 = 0; i3 < n3; i3++) {
            Array<BitmapFont.Glyph> glyphs = layout.runs.get(i3).glyphs;
            int nn = glyphs.size;
            for (int ii = 0; ii < nn; ii++) {
                int i4 = glyphs.get(ii).page;
                tempGlyphCount[i4] = tempGlyphCount[i4] + 1;
            }
        }
        int n4 = tempGlyphCount.length;
        for (int i5 = 0; i5 < n4; i5++) {
            requirePageGlyphs(i5, tempGlyphCount[i5]);
        }
    }

    private void requirePageGlyphs(int page, int glyphCount) {
        IntArray[] intArrayArr = this.pageGlyphIndices;
        if (intArrayArr != null && glyphCount > intArrayArr[page].items.length) {
            IntArray[] intArrayArr2 = this.pageGlyphIndices;
            intArrayArr2[page].ensureCapacity(glyphCount - intArrayArr2[page].size);
        }
        int[] iArr = this.idx;
        int vertexCount = iArr[page] + (glyphCount * 20);
        float[][] fArr = this.pageVertices;
        float[] vertices = fArr[page];
        if (vertices == null) {
            fArr[page] = new float[vertexCount];
        } else if (vertices.length < vertexCount) {
            float[] newVertices = new float[vertexCount];
            System.arraycopy(vertices, 0, newVertices, 0, iArr[page]);
            this.pageVertices[page] = newVertices;
        }
    }

    private void addToCache(GlyphLayout layout, float x, float y) {
        int pageCount = this.font.regions.size;
        float[][] fArr = this.pageVertices;
        if (fArr.length < pageCount) {
            float[][] newPageVertices = new float[pageCount];
            System.arraycopy(fArr, 0, newPageVertices, 0, fArr.length);
            this.pageVertices = newPageVertices;
            int[] newIdx = new int[pageCount];
            int[] iArr = this.idx;
            System.arraycopy(iArr, 0, newIdx, 0, iArr.length);
            this.idx = newIdx;
            IntArray[] newPageGlyphIndices = new IntArray[pageCount];
            int pageGlyphIndicesLength = 0;
            IntArray[] intArrayArr = this.pageGlyphIndices;
            if (intArrayArr != null) {
                pageGlyphIndicesLength = intArrayArr.length;
                System.arraycopy(intArrayArr, 0, newPageGlyphIndices, 0, intArrayArr.length);
            }
            for (int i = pageGlyphIndicesLength; i < pageCount; i++) {
                newPageGlyphIndices[i] = new IntArray();
            }
            this.pageGlyphIndices = newPageGlyphIndices;
            this.tempGlyphCount = new int[pageCount];
        }
        this.layouts.add(layout);
        requireGlyphs(layout);
        int n = layout.runs.size;
        for (int i2 = 0; i2 < n; i2++) {
            GlyphLayout.GlyphRun run = layout.runs.get(i2);
            Array<BitmapFont.Glyph> glyphs = run.glyphs;
            FloatArray xAdvances = run.xAdvances;
            float color = run.color.toFloatBits();
            float gx = x + run.x;
            float gy = y + run.y;
            int nn = glyphs.size;
            for (int ii = 0; ii < nn; ii++) {
                BitmapFont.Glyph glyph = glyphs.get(ii);
                gx += xAdvances.get(ii);
                addGlyph(glyph, gx, gy, color);
            }
        }
        this.currentTint = Color.WHITE_FLOAT_BITS;
    }

    private void addGlyph(BitmapFont.Glyph glyph, float x, float y, float color) {
        float scaleX = this.font.data.scaleX;
        float scaleY = this.font.data.scaleY;
        float x2 = x + (glyph.xoffset * scaleX);
        float y2 = y + (glyph.yoffset * scaleY);
        float width = glyph.width * scaleX;
        float height = glyph.height * scaleY;
        float u = glyph.u;
        float u2 = glyph.u2;
        float v = glyph.v;
        float v2 = glyph.v2;
        if (this.integer) {
            x2 = Math.round(x2);
            y2 = Math.round(y2);
            width = Math.round(width);
            height = Math.round(height);
        }
        float x22 = x2 + width;
        float y22 = y2 + height;
        int page = glyph.page;
        int[] iArr = this.idx;
        int idx = iArr[page];
        iArr[page] = iArr[page] + 20;
        IntArray[] intArrayArr = this.pageGlyphIndices;
        if (intArrayArr != null) {
            IntArray intArray = intArrayArr[page];
            int i = this.glyphCount;
            this.glyphCount = i + 1;
            intArray.add(i);
        }
        float[] vertices = this.pageVertices[page];
        int idx2 = idx + 1;
        vertices[idx] = x2;
        int idx3 = idx2 + 1;
        vertices[idx2] = y2;
        int idx4 = idx3 + 1;
        vertices[idx3] = color;
        int idx5 = idx4 + 1;
        vertices[idx4] = u;
        int idx6 = idx5 + 1;
        vertices[idx5] = v;
        int idx7 = idx6 + 1;
        vertices[idx6] = x2;
        int idx8 = idx7 + 1;
        vertices[idx7] = y22;
        int idx9 = idx8 + 1;
        vertices[idx8] = color;
        int idx10 = idx9 + 1;
        vertices[idx9] = u;
        int idx11 = idx10 + 1;
        vertices[idx10] = v2;
        int idx12 = idx11 + 1;
        vertices[idx11] = x22;
        int idx13 = idx12 + 1;
        vertices[idx12] = y22;
        int idx14 = idx13 + 1;
        vertices[idx13] = color;
        int idx15 = idx14 + 1;
        vertices[idx14] = u2;
        int idx16 = idx15 + 1;
        vertices[idx15] = v2;
        int idx17 = idx16 + 1;
        vertices[idx16] = x22;
        int idx18 = idx17 + 1;
        vertices[idx17] = y2;
        int idx19 = idx18 + 1;
        vertices[idx18] = color;
        vertices[idx19] = u2;
        vertices[idx19 + 1] = v;
    }

    public GlyphLayout setText(CharSequence str, float x, float y) {
        clear();
        return addText(str, x, y, 0, str.length(), 0.0f, 8, false);
    }

    public GlyphLayout setText(CharSequence str, float x, float y, float targetWidth, int halign, boolean wrap) {
        clear();
        return addText(str, x, y, 0, str.length(), targetWidth, halign, wrap);
    }

    public GlyphLayout setText(CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap) {
        clear();
        return addText(str, x, y, start, end, targetWidth, halign, wrap);
    }

    public GlyphLayout setText(CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap, String truncate) {
        clear();
        return addText(str, x, y, start, end, targetWidth, halign, wrap, truncate);
    }

    public void setText(GlyphLayout layout, float x, float y) {
        clear();
        addText(layout, x, y);
    }

    public GlyphLayout addText(CharSequence str, float x, float y) {
        return addText(str, x, y, 0, str.length(), 0.0f, 8, false, null);
    }

    public GlyphLayout addText(CharSequence str, float x, float y, float targetWidth, int halign, boolean wrap) {
        return addText(str, x, y, 0, str.length(), targetWidth, halign, wrap, null);
    }

    public GlyphLayout addText(CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap) {
        return addText(str, x, y, start, end, targetWidth, halign, wrap, null);
    }

    public GlyphLayout addText(CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap, String truncate) {
        GlyphLayout layout = (GlyphLayout) Pools.obtain(GlyphLayout.class);
        this.pooledLayouts.add(layout);
        layout.setText(this.font, str, start, end, this.color, targetWidth, halign, wrap, truncate);
        addText(layout, x, y);
        return layout;
    }

    public void addText(GlyphLayout layout, float x, float y) {
        addToCache(layout, x, this.font.data.ascent + y);
    }

    public float getX() {
        return this.x;
    }

    public float getY() {
        return this.y;
    }

    public BitmapFont getFont() {
        return this.font;
    }

    public void setUseIntegerPositions(boolean use) {
        this.integer = use;
    }

    public boolean usesIntegerPositions() {
        return this.integer;
    }

    public float[] getVertices() {
        return getVertices(0);
    }

    public float[] getVertices(int page) {
        return this.pageVertices[page];
    }

    public int getVertexCount(int page) {
        return this.idx[page];
    }

    public Array<GlyphLayout> getLayouts() {
        return this.layouts;
    }
}