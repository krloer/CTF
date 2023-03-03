package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Colors;
import com.badlogic.gdx.graphics.g2d.BitmapFont;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.Pool;
import com.badlogic.gdx.utils.Pools;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class GlyphLayout implements Pool.Poolable {
    private static final float epsilon = 1.0E-4f;
    public float height;
    public final Array<GlyphRun> runs = new Array<>(1);
    public float width;
    private static final Pool<GlyphRun> glyphRunPool = Pools.get(GlyphRun.class);
    private static final Pool<Color> colorPool = Pools.get(Color.class);
    private static final Array<Color> colorStack = new Array<>(4);

    public GlyphLayout() {
    }

    public GlyphLayout(BitmapFont font, CharSequence str) {
        setText(font, str);
    }

    public GlyphLayout(BitmapFont font, CharSequence str, Color color, float targetWidth, int halign, boolean wrap) {
        setText(font, str, color, targetWidth, halign, wrap);
    }

    public GlyphLayout(BitmapFont font, CharSequence str, int start, int end, Color color, float targetWidth, int halign, boolean wrap, String truncate) {
        setText(font, str, start, end, color, targetWidth, halign, wrap, truncate);
    }

    public void setText(BitmapFont font, CharSequence str) {
        setText(font, str, 0, str.length(), font.getColor(), 0.0f, 8, false, null);
    }

    public void setText(BitmapFont font, CharSequence str, Color color, float targetWidth, int halign, boolean wrap) {
        setText(font, str, 0, str.length(), color, targetWidth, halign, wrap, null);
    }

    public void setText(BitmapFont font, CharSequence str, int start, int end, Color color, float targetWidth, int halign, boolean wrap, String truncate) {
        boolean wrap2;
        Color color2;
        float y;
        Color nextColor;
        int runEnd;
        int start2;
        boolean wrap3;
        boolean markupEnabled;
        float y2;
        int runStart;
        float x;
        GlyphRun next;
        int n;
        CharSequence charSequence = str;
        int i = end;
        Array<GlyphRun> runs = this.runs;
        glyphRunPool.freeAll(runs);
        runs.clear();
        BitmapFont.BitmapFontData fontData = font.data;
        int length = start;
        if (length == i) {
            this.width = 0.0f;
            this.height = fontData.capHeight;
            return;
        }
        if (truncate != null) {
            wrap2 = true;
        } else if (targetWidth > fontData.spaceXadvance * 3.0f) {
            wrap2 = wrap;
        } else {
            wrap2 = false;
        }
        Color nextColor2 = color;
        boolean markupEnabled2 = fontData.markupEnabled;
        if (!markupEnabled2) {
            color2 = color;
        } else {
            int n2 = colorStack.size;
            for (int i2 = 1; i2 < n2; i2++) {
                colorPool.free(colorStack.get(i2));
            }
            colorStack.clear();
            color2 = color;
            colorStack.add(color2);
        }
        float down = fontData.down;
        float x2 = 0.0f;
        float x3 = 0.0f;
        BitmapFont.Glyph lastGlyph = null;
        int runStart2 = start;
        loop1: while (true) {
            boolean newline = false;
            if (length == i) {
                if (runStart2 == i) {
                    y = x3;
                    break;
                }
                nextColor = nextColor2;
                runEnd = end;
                start2 = length;
            } else {
                int start3 = length + 1;
                int start4 = charSequence.charAt(length);
                if (start4 == 10) {
                    int runEnd2 = start3 - 1;
                    newline = true;
                    runEnd = runEnd2;
                    nextColor = nextColor2;
                    start2 = start3;
                } else {
                    if (start4 == 91 && markupEnabled2) {
                        int length2 = parseColorMarkup(charSequence, start3, i, colorPool);
                        if (length2 >= 0) {
                            runEnd = start3 - 1;
                            int runEnd3 = length2 + 1;
                            int start5 = start3 + runEnd3;
                            Color nextColor3 = colorStack.peek();
                            nextColor = nextColor3;
                            start2 = start5;
                        } else if (length2 == -2) {
                            length = start3 + 1;
                        }
                    }
                    nextColor = nextColor2;
                    runEnd = -1;
                    start2 = start3;
                }
            }
            if (runEnd != -1) {
                if (runEnd == runStart2) {
                    y2 = x3;
                    runStart = runStart2;
                    wrap3 = wrap2;
                    markupEnabled = markupEnabled2;
                } else {
                    GlyphRun run = glyphRunPool.obtain();
                    run.color.set(color2);
                    y2 = x3;
                    BitmapFont.Glyph lastGlyph2 = lastGlyph;
                    runStart = runStart2;
                    fontData.getGlyphs(run, str, runStart2, runEnd, lastGlyph2);
                    if (run.glyphs.size == 0) {
                        glyphRunPool.free(run);
                        lastGlyph = lastGlyph2;
                        wrap3 = wrap2;
                        markupEnabled = markupEnabled2;
                    } else {
                        if (lastGlyph2 == null) {
                            x = x2;
                        } else {
                            x = x2 - (lastGlyph2.fixedWidth ? lastGlyph2.xadvance * fontData.scaleX : ((lastGlyph2.width + lastGlyph2.xoffset) * fontData.scaleX) - fontData.padRight);
                        }
                        BitmapFont.Glyph lastGlyph3 = run.glyphs.peek();
                        lastGlyph = lastGlyph3;
                        run.x = x;
                        run.y = y2;
                        if (newline || runEnd == i) {
                            adjustLastGlyph(fontData, run);
                        }
                        runs.add(run);
                        int n3 = run.xAdvances.size;
                        float[] xAdvances = run.xAdvances.items;
                        if (!wrap2) {
                            wrap3 = wrap2;
                            markupEnabled = markupEnabled2;
                        } else if (n3 != 0) {
                            float x4 = x + xAdvances[0] + xAdvances[1];
                            float[] xAdvances2 = xAdvances;
                            BitmapFont.Glyph lastGlyph4 = lastGlyph;
                            GlyphRun run2 = run;
                            y = y2;
                            int n4 = n3;
                            int i3 = 2;
                            while (true) {
                                if (i3 >= n4) {
                                    wrap3 = wrap2;
                                    markupEnabled = markupEnabled2;
                                    x2 = x4;
                                    y2 = y;
                                    lastGlyph = lastGlyph4;
                                    break;
                                }
                                BitmapFont.Glyph glyph = run2.glyphs.get(i3 - 1);
                                float glyphWidth = ((glyph.width + glyph.xoffset) * fontData.scaleX) - fontData.padRight;
                                if ((x4 + glyphWidth) - epsilon <= targetWidth) {
                                    x4 += xAdvances2[i3];
                                    n = n4;
                                    wrap3 = wrap2;
                                    markupEnabled = markupEnabled2;
                                } else if (truncate != null) {
                                    truncate(fontData, run2, targetWidth, truncate, i3, glyphRunPool);
                                    length = start2;
                                    nextColor2 = nextColor;
                                    break loop1;
                                } else {
                                    GlyphRun run3 = run2;
                                    wrap3 = wrap2;
                                    markupEnabled = markupEnabled2;
                                    float y3 = y + down;
                                    lastGlyph = null;
                                    int wrapIndex = fontData.getWrapIndex(run3.glyphs, i3);
                                    if ((wrapIndex == 0 && run3.x == 0.0f) || wrapIndex >= run3.glyphs.size) {
                                        wrapIndex = i3 - 1;
                                    }
                                    if (wrapIndex == 0) {
                                        next = run3;
                                        int glyphCount = run3.glyphs.size;
                                        while (wrapIndex < glyphCount && fontData.isWhitespace((char) run3.glyphs.get(wrapIndex).id)) {
                                            wrapIndex++;
                                        }
                                        if (wrapIndex > 0) {
                                            run3.glyphs.removeRange(0, wrapIndex - 1);
                                            run3.xAdvances.removeRange(1, wrapIndex);
                                        }
                                        xAdvances2[0] = ((-run3.glyphs.first().xoffset) * fontData.scaleX) - fontData.padLeft;
                                        if (runs.size > 1) {
                                            GlyphRun previous = runs.get(runs.size - 2);
                                            int lastIndex = previous.glyphs.size - 1;
                                            while (lastIndex > 0 && fontData.isWhitespace((char) previous.glyphs.get(lastIndex).id)) {
                                                lastIndex--;
                                            }
                                            previous.glyphs.truncate(lastIndex + 1);
                                            previous.xAdvances.truncate(lastIndex + 2);
                                            adjustLastGlyph(fontData, previous);
                                        }
                                    } else {
                                        next = wrap(fontData, run3, wrapIndex, i3);
                                        if (next == null) {
                                            y2 = y3;
                                            x2 = 0.0f;
                                            break;
                                        }
                                        runs.add(next);
                                    }
                                    n = next.xAdvances.size;
                                    float[] xAdvances3 = next.xAdvances.items;
                                    float x5 = xAdvances3[0];
                                    if (n > 1) {
                                        x5 += xAdvances3[1];
                                    }
                                    next.x = 0.0f;
                                    next.y = y3;
                                    i3 = 1;
                                    y = y3;
                                    lastGlyph4 = null;
                                    xAdvances2 = xAdvances3;
                                    run2 = next;
                                    x4 = x5;
                                }
                                i3++;
                                n4 = n;
                                wrap2 = wrap3;
                                markupEnabled2 = markupEnabled;
                            }
                        } else {
                            wrap3 = wrap2;
                            markupEnabled = markupEnabled2;
                        }
                        if (!markupEnabled) {
                            x2 = x;
                        } else {
                            x2 = x;
                            for (int i4 = 0; i4 < n3; i4++) {
                                x2 += xAdvances[i4];
                            }
                        }
                    }
                }
                if (newline) {
                    x2 = 0.0f;
                    if (runEnd == runStart) {
                        y2 += fontData.blankLineScale * down;
                    } else {
                        y2 += down;
                    }
                    lastGlyph = null;
                }
                runStart2 = start2;
                color2 = nextColor;
                x3 = y2;
            } else {
                wrap3 = wrap2;
                markupEnabled = markupEnabled2;
            }
            charSequence = str;
            i = end;
            length = start2;
            nextColor2 = nextColor;
            wrap2 = wrap3;
            markupEnabled2 = markupEnabled;
        }
        this.height = fontData.capHeight + Math.abs(y);
        float width = 0.0f;
        Object[] runsItems = runs.items;
        int runsSize = runs.size;
        int i5 = 0;
        while (i5 < runsSize) {
            GlyphRun run4 = (GlyphRun) runsItems[i5];
            float[] xAdvances4 = run4.xAdvances.items;
            float runWidth = xAdvances4[0];
            int start6 = length;
            Object[] glyphs = run4.glyphs.items;
            Color nextColor4 = nextColor2;
            int nn = run4.glyphs.size;
            boolean wrap4 = wrap2;
            float max = 0.0f;
            int ii = 0;
            while (ii < nn) {
                Object[] glyphs2 = glyphs;
                BitmapFont.Glyph glyph2 = (BitmapFont.Glyph) glyphs[ii];
                int nn2 = nn;
                int nn3 = glyph2.width;
                float glyphWidth2 = ((nn3 + glyph2.xoffset) * fontData.scaleX) - fontData.padRight;
                max = Math.max(max, runWidth + glyphWidth2);
                ii++;
                runWidth += xAdvances4[ii];
                nn = nn2;
                glyphs = glyphs2;
                markupEnabled2 = markupEnabled2;
            }
            run4.width = Math.max(runWidth, max);
            width = Math.max(width, run4.x + run4.width);
            i5++;
            length = start6;
            nextColor2 = nextColor4;
            wrap2 = wrap4;
        }
        this.width = width;
        if ((halign & 8) == 0) {
            boolean center = (halign & 1) != 0;
            float lineWidth = 0.0f;
            float lineY = -2.14748365E9f;
            int lineStart = 0;
            for (int i6 = 0; i6 < runsSize; i6++) {
                GlyphRun run5 = (GlyphRun) runsItems[i6];
                if (run5.y != lineY) {
                    lineY = run5.y;
                    float shift = targetWidth - lineWidth;
                    if (center) {
                        shift /= 2.0f;
                    }
                    while (lineStart < i6) {
                        int lineStart2 = lineStart + 1;
                        ((GlyphRun) runsItems[lineStart]).x += shift;
                        lineStart = lineStart2;
                    }
                    float lineWidth2 = run5.x + run5.width;
                    lineWidth = lineWidth2;
                } else {
                    float lineWidth3 = run5.x;
                    lineWidth = Math.max(lineWidth, lineWidth3 + run5.width);
                }
            }
            float shift2 = targetWidth - lineWidth;
            if (center) {
                shift2 /= 2.0f;
            }
            while (lineStart < runsSize) {
                int lineStart3 = lineStart + 1;
                ((GlyphRun) runsItems[lineStart]).x += shift2;
                lineStart = lineStart3;
            }
        }
    }

    private void truncate(BitmapFont.BitmapFontData fontData, GlyphRun run, float targetWidth, String truncate, int widthIndex, Pool<GlyphRun> glyphRunPool2) {
        GlyphRun truncateRun = glyphRunPool2.obtain();
        fontData.getGlyphs(truncateRun, truncate, 0, truncate.length(), null);
        float truncateWidth = 0.0f;
        if (truncateRun.xAdvances.size > 0) {
            adjustLastGlyph(fontData, truncateRun);
            float[] xAdvances = truncateRun.xAdvances.items;
            int n = truncateRun.xAdvances.size;
            for (int i = 1; i < n; i++) {
                truncateWidth += xAdvances[i];
            }
        }
        float targetWidth2 = targetWidth - truncateWidth;
        int count = 0;
        float width = run.x;
        float[] xAdvances2 = run.xAdvances.items;
        while (count < run.xAdvances.size) {
            float xAdvance = xAdvances2[count];
            width += xAdvance;
            if (width > targetWidth2) {
                break;
            }
            count++;
        }
        if (count > 1) {
            run.glyphs.truncate(count - 1);
            run.xAdvances.truncate(count);
            adjustLastGlyph(fontData, run);
            if (truncateRun.xAdvances.size > 0) {
                run.xAdvances.addAll(truncateRun.xAdvances, 1, truncateRun.xAdvances.size - 1);
            }
        } else {
            run.glyphs.clear();
            run.xAdvances.clear();
            run.xAdvances.addAll(truncateRun.xAdvances);
        }
        run.glyphs.addAll(truncateRun.glyphs);
        glyphRunPool2.free(truncateRun);
    }

    private GlyphRun wrap(BitmapFont.BitmapFontData fontData, GlyphRun first, int wrapIndex, int widthIndex) {
        Array<BitmapFont.Glyph> glyphs2 = first.glyphs;
        int glyphCount = first.glyphs.size;
        FloatArray xAdvances2 = first.xAdvances;
        int firstEnd = wrapIndex;
        while (firstEnd > 0 && fontData.isWhitespace((char) glyphs2.get(firstEnd - 1).id)) {
            firstEnd--;
        }
        int secondStart = wrapIndex;
        while (secondStart < glyphCount && fontData.isWhitespace((char) glyphs2.get(secondStart).id)) {
            secondStart++;
        }
        GlyphRun second = null;
        if (secondStart < glyphCount) {
            GlyphRun second2 = glyphRunPool.obtain();
            second = second2;
            second.color.set(first.color);
            Array<BitmapFont.Glyph> glyphs1 = second.glyphs;
            glyphs1.addAll(glyphs2, 0, firstEnd);
            glyphs2.removeRange(0, secondStart - 1);
            first.glyphs = glyphs1;
            second.glyphs = glyphs2;
            FloatArray xAdvances1 = second.xAdvances;
            xAdvances1.addAll(xAdvances2, 0, firstEnd + 1);
            xAdvances2.removeRange(1, secondStart);
            xAdvances2.items[0] = ((-glyphs2.first().xoffset) * fontData.scaleX) - fontData.padLeft;
            first.xAdvances = xAdvances1;
            second.xAdvances = xAdvances2;
        } else {
            glyphs2.truncate(firstEnd);
            xAdvances2.truncate(firstEnd + 1);
        }
        if (firstEnd == 0) {
            glyphRunPool.free(first);
            this.runs.pop();
        } else {
            adjustLastGlyph(fontData, first);
        }
        return second;
    }

    private void adjustLastGlyph(BitmapFont.BitmapFontData fontData, GlyphRun run) {
        BitmapFont.Glyph last = run.glyphs.peek();
        if (last.fixedWidth) {
            return;
        }
        float width = ((last.width + last.xoffset) * fontData.scaleX) - fontData.padRight;
        run.xAdvances.items[run.xAdvances.size - 1] = width;
    }

    private int parseColorMarkup(CharSequence str, int start, int end, Pool<Color> colorPool2) {
        int i;
        int i2;
        if (start == end) {
            return -1;
        }
        char charAt = str.charAt(start);
        if (charAt != '#') {
            if (charAt != '[') {
                if (charAt == ']') {
                    if (colorStack.size > 1) {
                        colorPool2.free(colorStack.pop());
                        return 0;
                    }
                    return 0;
                }
                for (int i3 = start + 1; i3 < end; i3++) {
                    if (str.charAt(i3) == ']') {
                        Color namedColor = Colors.get(str.subSequence(start, i3).toString());
                        if (namedColor == null) {
                            return -1;
                        }
                        Color color = colorPool2.obtain();
                        colorStack.add(color);
                        color.set(namedColor);
                        return i3 - start;
                    }
                }
                return -1;
            }
            return -2;
        }
        int colorInt = 0;
        int i4 = start + 1;
        while (true) {
            if (i4 >= end) {
                break;
            }
            char ch = str.charAt(i4);
            if (ch == ']') {
                if (i4 >= start + 2 && i4 <= start + 9) {
                    if (i4 - start <= 7) {
                        int nn = 9 - (i4 - start);
                        for (int ii = 0; ii < nn; ii++) {
                            colorInt <<= 4;
                        }
                        colorInt |= 255;
                    }
                    Color color2 = colorPool2.obtain();
                    colorStack.add(color2);
                    Color.rgba8888ToColor(color2, colorInt);
                    return i4 - start;
                }
            } else {
                if (ch >= '0' && ch <= '9') {
                    i = colorInt * 16;
                    i2 = ch - '0';
                } else if (ch >= 'a' && ch <= 'f') {
                    i = colorInt * 16;
                    i2 = ch - 'W';
                } else if (ch < 'A' || ch > 'F') {
                    break;
                } else {
                    i = colorInt * 16;
                    i2 = ch - '7';
                }
                colorInt = i + i2;
                i4++;
            }
        }
        return -1;
    }

    @Override // com.badlogic.gdx.utils.Pool.Poolable
    public void reset() {
        Pools.get(GlyphRun.class).freeAll(this.runs);
        this.runs.clear();
        this.width = 0.0f;
        this.height = 0.0f;
    }

    public String toString() {
        if (this.runs.size == 0) {
            return BuildConfig.FLAVOR;
        }
        StringBuilder buffer = new StringBuilder(128);
        buffer.append(this.width);
        buffer.append('x');
        buffer.append(this.height);
        buffer.append('\n');
        int n = this.runs.size;
        for (int i = 0; i < n; i++) {
            buffer.append(this.runs.get(i).toString());
            buffer.append('\n');
        }
        buffer.setLength(buffer.length() - 1);
        return buffer.toString();
    }

    /* loaded from: classes.dex */
    public static class GlyphRun implements Pool.Poolable {
        public float width;
        public float x;
        public float y;
        public Array<BitmapFont.Glyph> glyphs = new Array<>();
        public FloatArray xAdvances = new FloatArray();
        public final Color color = new Color();

        @Override // com.badlogic.gdx.utils.Pool.Poolable
        public void reset() {
            this.glyphs.clear();
            this.xAdvances.clear();
            this.width = 0.0f;
        }

        public String toString() {
            StringBuilder buffer = new StringBuilder(this.glyphs.size + 32);
            Array<BitmapFont.Glyph> glyphs = this.glyphs;
            int n = glyphs.size;
            for (int i = 0; i < n; i++) {
                BitmapFont.Glyph g = glyphs.get(i);
                buffer.append((char) g.id);
            }
            buffer.append(", #");
            buffer.append(this.color);
            buffer.append(", ");
            buffer.append(this.x);
            buffer.append(", ");
            buffer.append(this.y);
            buffer.append(", ");
            buffer.append(this.width);
            return buffer.toString();
        }
    }
}