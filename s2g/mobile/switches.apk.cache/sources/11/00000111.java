package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.GlyphLayout;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public class BitmapFont implements Disposable {
    private static final int LOG2_PAGE_SIZE = 9;
    private static final int PAGES = 128;
    private static final int PAGE_SIZE = 512;
    private final BitmapFontCache cache;
    final BitmapFontData data;
    private boolean flipped;
    boolean integer;
    private boolean ownsTexture;
    Array<TextureRegion> regions;

    public BitmapFont() {
        this(Gdx.files.classpath("com/badlogic/gdx/utils/arial-15.fnt"), Gdx.files.classpath("com/badlogic/gdx/utils/arial-15.png"), false, true);
    }

    public BitmapFont(boolean flip) {
        this(Gdx.files.classpath("com/badlogic/gdx/utils/arial-15.fnt"), Gdx.files.classpath("com/badlogic/gdx/utils/arial-15.png"), flip, true);
    }

    public BitmapFont(FileHandle fontFile, TextureRegion region) {
        this(fontFile, region, false);
    }

    public BitmapFont(FileHandle fontFile, TextureRegion region, boolean flip) {
        this(new BitmapFontData(fontFile, flip), region, true);
    }

    public BitmapFont(FileHandle fontFile) {
        this(fontFile, false);
    }

    public BitmapFont(FileHandle fontFile, boolean flip) {
        this(new BitmapFontData(fontFile, flip), (TextureRegion) null, true);
    }

    public BitmapFont(FileHandle fontFile, FileHandle imageFile, boolean flip) {
        this(fontFile, imageFile, flip, true);
    }

    public BitmapFont(FileHandle fontFile, FileHandle imageFile, boolean flip, boolean integer) {
        this(new BitmapFontData(fontFile, flip), new TextureRegion(new Texture(imageFile, false)), integer);
        this.ownsTexture = true;
    }

    public BitmapFont(BitmapFontData data, TextureRegion region, boolean integer) {
        this(data, region != null ? Array.with(region) : null, integer);
    }

    public BitmapFont(BitmapFontData data, Array<TextureRegion> pageRegions, boolean integer) {
        FileHandle file;
        this.flipped = data.flipped;
        this.data = data;
        this.integer = integer;
        if (pageRegions == null || pageRegions.size == 0) {
            if (data.imagePaths == null) {
                throw new IllegalArgumentException("If no regions are specified, the font data must have an images path.");
            }
            int n = data.imagePaths.length;
            this.regions = new Array<>(n);
            for (int i = 0; i < n; i++) {
                if (data.fontFile == null) {
                    file = Gdx.files.internal(data.imagePaths[i]);
                } else {
                    file = Gdx.files.getFileHandle(data.imagePaths[i], data.fontFile.type());
                }
                this.regions.add(new TextureRegion(new Texture(file, false)));
            }
            this.ownsTexture = true;
        } else {
            this.regions = pageRegions;
            this.ownsTexture = false;
        }
        this.cache = newFontCache();
        load(data);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void load(BitmapFontData data) {
        Glyph[][] glyphArr;
        for (Glyph[] page : data.glyphs) {
            if (page != null) {
                for (Glyph glyph : page) {
                    if (glyph != null) {
                        data.setGlyphRegion(glyph, this.regions.get(glyph.page));
                    }
                }
            }
        }
        if (data.missingGlyph != null) {
            data.setGlyphRegion(data.missingGlyph, this.regions.get(data.missingGlyph.page));
        }
    }

    public GlyphLayout draw(Batch batch, CharSequence str, float x, float y) {
        this.cache.clear();
        GlyphLayout layout = this.cache.addText(str, x, y);
        this.cache.draw(batch);
        return layout;
    }

    public GlyphLayout draw(Batch batch, CharSequence str, float x, float y, float targetWidth, int halign, boolean wrap) {
        this.cache.clear();
        GlyphLayout layout = this.cache.addText(str, x, y, targetWidth, halign, wrap);
        this.cache.draw(batch);
        return layout;
    }

    public GlyphLayout draw(Batch batch, CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap) {
        this.cache.clear();
        GlyphLayout layout = this.cache.addText(str, x, y, start, end, targetWidth, halign, wrap);
        this.cache.draw(batch);
        return layout;
    }

    public GlyphLayout draw(Batch batch, CharSequence str, float x, float y, int start, int end, float targetWidth, int halign, boolean wrap, String truncate) {
        this.cache.clear();
        GlyphLayout layout = this.cache.addText(str, x, y, start, end, targetWidth, halign, wrap, truncate);
        this.cache.draw(batch);
        return layout;
    }

    public void draw(Batch batch, GlyphLayout layout, float x, float y) {
        this.cache.clear();
        this.cache.addText(layout, x, y);
        this.cache.draw(batch);
    }

    public Color getColor() {
        return this.cache.getColor();
    }

    public void setColor(Color color) {
        this.cache.getColor().set(color);
    }

    public void setColor(float r, float g, float b, float a) {
        this.cache.getColor().set(r, g, b, a);
    }

    public float getScaleX() {
        return this.data.scaleX;
    }

    public float getScaleY() {
        return this.data.scaleY;
    }

    public TextureRegion getRegion() {
        return this.regions.first();
    }

    public Array<TextureRegion> getRegions() {
        return this.regions;
    }

    public TextureRegion getRegion(int index) {
        return this.regions.get(index);
    }

    public float getLineHeight() {
        return this.data.lineHeight;
    }

    public float getSpaceXadvance() {
        return this.data.spaceXadvance;
    }

    public float getXHeight() {
        return this.data.xHeight;
    }

    public float getCapHeight() {
        return this.data.capHeight;
    }

    public float getAscent() {
        return this.data.ascent;
    }

    public float getDescent() {
        return this.data.descent;
    }

    public boolean isFlipped() {
        return this.flipped;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (this.ownsTexture) {
            for (int i = 0; i < this.regions.size; i++) {
                this.regions.get(i).getTexture().dispose();
            }
        }
    }

    public void setFixedWidthGlyphs(CharSequence glyphs) {
        BitmapFontData data = this.data;
        int maxAdvance = 0;
        int end = glyphs.length();
        for (int index = 0; index < end; index++) {
            Glyph g = data.getGlyph(glyphs.charAt(index));
            if (g != null && g.xadvance > maxAdvance) {
                maxAdvance = g.xadvance;
            }
        }
        int end2 = glyphs.length();
        for (int index2 = 0; index2 < end2; index2++) {
            Glyph g2 = data.getGlyph(glyphs.charAt(index2));
            if (g2 != null) {
                g2.xoffset += (maxAdvance - g2.xadvance) / 2;
                g2.xadvance = maxAdvance;
                g2.kerning = null;
                g2.fixedWidth = true;
            }
        }
    }

    public void setUseIntegerPositions(boolean integer) {
        this.integer = integer;
        this.cache.setUseIntegerPositions(integer);
    }

    public boolean usesIntegerPositions() {
        return this.integer;
    }

    public BitmapFontCache getCache() {
        return this.cache;
    }

    public BitmapFontData getData() {
        return this.data;
    }

    public boolean ownsTexture() {
        return this.ownsTexture;
    }

    public void setOwnsTexture(boolean ownsTexture) {
        this.ownsTexture = ownsTexture;
    }

    public BitmapFontCache newFontCache() {
        return new BitmapFontCache(this, this.integer);
    }

    public String toString() {
        return this.data.name != null ? this.data.name : super.toString();
    }

    /* loaded from: classes.dex */
    public static class Glyph {
        public boolean fixedWidth;
        public int height;
        public int id;
        public byte[][] kerning;
        public int page = 0;
        public int srcX;
        public int srcY;
        public float u;
        public float u2;
        public float v;
        public float v2;
        public int width;
        public int xadvance;
        public int xoffset;
        public int yoffset;

        public int getKerning(char ch) {
            byte[] page;
            byte[][] bArr = this.kerning;
            if (bArr == null || (page = bArr[ch >>> '\t']) == null) {
                return 0;
            }
            return page[ch & 511];
        }

        public void setKerning(int ch, int value) {
            if (this.kerning == null) {
                this.kerning = new byte[128];
            }
            byte[][] bArr = this.kerning;
            byte[] page = bArr[ch >>> 9];
            if (page == null) {
                byte[] bArr2 = new byte[512];
                page = bArr2;
                bArr[ch >>> 9] = bArr2;
            }
            page[ch & 511] = (byte) value;
        }

        public String toString() {
            return Character.toString((char) this.id);
        }
    }

    static int indexOf(CharSequence text, char ch, int start) {
        int n = text.length();
        while (start < n) {
            if (text.charAt(start) == ch) {
                return start;
            }
            start++;
        }
        return n;
    }

    /* loaded from: classes.dex */
    public static class BitmapFontData {
        public float ascent;
        public float blankLineScale;
        public char[] breakChars;
        public char[] capChars;
        public float capHeight;
        public float cursorX;
        public float descent;
        public float down;
        public boolean flipped;
        public FileHandle fontFile;
        public final Glyph[][] glyphs;
        public String[] imagePaths;
        public float lineHeight;
        public boolean markupEnabled;
        public Glyph missingGlyph;
        public String name;
        public float padBottom;
        public float padLeft;
        public float padRight;
        public float padTop;
        public float scaleX;
        public float scaleY;
        public float spaceXadvance;
        public char[] xChars;
        public float xHeight;

        public BitmapFontData() {
            this.capHeight = 1.0f;
            this.blankLineScale = 1.0f;
            this.scaleX = 1.0f;
            this.scaleY = 1.0f;
            this.glyphs = new Glyph[128];
            this.xHeight = 1.0f;
            this.xChars = new char[]{'x', 'e', 'a', 'o', 'n', 's', 'r', 'c', 'u', 'm', 'v', 'w', 'z'};
            this.capChars = new char[]{'M', 'N', 'B', 'D', 'C', 'E', 'F', 'K', 'A', 'G', 'H', 'I', 'J', 'L', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
        }

        public BitmapFontData(FileHandle fontFile, boolean flip) {
            this.capHeight = 1.0f;
            this.blankLineScale = 1.0f;
            this.scaleX = 1.0f;
            this.scaleY = 1.0f;
            this.glyphs = new Glyph[128];
            this.xHeight = 1.0f;
            this.xChars = new char[]{'x', 'e', 'a', 'o', 'n', 's', 'r', 'c', 'u', 'm', 'v', 'w', 'z'};
            this.capChars = new char[]{'M', 'N', 'B', 'D', 'C', 'E', 'F', 'K', 'A', 'G', 'H', 'I', 'J', 'L', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
            this.fontFile = fontFile;
            this.flipped = flip;
            load(fontFile, flip);
        }

        public void load(FileHandle fontFile, boolean flip) {
            BufferedReader reader;
            Throwable th;
            Exception ex;
            String line;
            float overrideLineHeight;
            float overrideSpaceXAdvance;
            float overrideXHeight;
            Glyph capGlyph;
            BufferedReader reader2;
            float overrideXHeight2;
            float overrideSpaceXAdvance2;
            int i;
            float overrideXHeight3;
            float overrideSpaceXAdvance3;
            float overrideSpaceXAdvance4;
            int i2;
            if (this.imagePaths != null) {
                throw new IllegalStateException("Already loaded.");
            }
            this.name = fontFile.nameWithoutExtension();
            BufferedReader reader3 = new BufferedReader(new InputStreamReader(fontFile.read()), 512);
            try {
                try {
                    String line2 = reader3.readLine();
                    try {
                        if (line2 == null) {
                            throw new GdxRuntimeException("File is empty.");
                        }
                        String line3 = line2.substring(line2.indexOf("padding=") + 8);
                        String[] padding = line3.substring(0, line3.indexOf(32)).split(",", 4);
                        if (padding.length != 4) {
                            throw new GdxRuntimeException("Invalid padding.");
                        }
                        this.padTop = Integer.parseInt(padding[0]);
                        int i3 = 1;
                        this.padRight = Integer.parseInt(padding[1]);
                        this.padBottom = Integer.parseInt(padding[2]);
                        this.padLeft = Integer.parseInt(padding[3]);
                        float padY = this.padTop + this.padBottom;
                        String line4 = reader3.readLine();
                        if (line4 == null) {
                            throw new GdxRuntimeException("Missing common header.");
                        }
                        String[] common = line4.split(" ", 9);
                        if (common.length < 3) {
                            throw new GdxRuntimeException("Invalid common header.");
                        }
                        if (!common[1].startsWith("lineHeight=")) {
                            throw new GdxRuntimeException("Missing: lineHeight");
                        }
                        this.lineHeight = Integer.parseInt(common[1].substring(11));
                        if (!common[2].startsWith("base=")) {
                            throw new GdxRuntimeException("Missing: base");
                        }
                        float baseLine = Integer.parseInt(common[2].substring(5));
                        int pageCount = 1;
                        if (common.length >= 6) {
                            try {
                                if (common[5] != null && common[5].startsWith("pages=")) {
                                    try {
                                        pageCount = Math.max(1, Integer.parseInt(common[5].substring(6)));
                                    } catch (NumberFormatException e) {
                                    }
                                }
                            } catch (Exception e2) {
                                reader = reader3;
                                ex = e2;
                                StringBuilder sb = new StringBuilder();
                                sb.append("Error loading font file: ");
                                try {
                                    sb.append(fontFile);
                                    throw new GdxRuntimeException(sb.toString(), ex);
                                } catch (Throwable th2) {
                                    th = th2;
                                    StreamUtils.closeQuietly(reader);
                                    throw th;
                                }
                            } catch (Throwable th3) {
                                reader = reader3;
                                th = th3;
                                StreamUtils.closeQuietly(reader);
                                throw th;
                            }
                        }
                        this.imagePaths = new String[pageCount];
                        int p = 0;
                        while (p < pageCount) {
                            String line5 = reader3.readLine();
                            if (line5 == null) {
                                throw new GdxRuntimeException("Missing additional page definitions.");
                            }
                            Matcher matcher = Pattern.compile(".*id=(\\d+)").matcher(line5);
                            if (matcher.find()) {
                                String id = matcher.group(i3);
                                try {
                                    int pageID = Integer.parseInt(id);
                                    if (pageID != p) {
                                        throw new GdxRuntimeException("Page IDs must be indices starting at 0: " + id);
                                    }
                                } catch (NumberFormatException ex2) {
                                    throw new GdxRuntimeException("Invalid page id: " + id, ex2);
                                }
                            }
                            Matcher matcher2 = Pattern.compile(".*file=\"?([^\"]+)\"?").matcher(line5);
                            if (!matcher2.find()) {
                                throw new GdxRuntimeException("Missing: file");
                            }
                            String fileName = matcher2.group(i3);
                            this.imagePaths[p] = fontFile.parent().child(fileName).path().replaceAll("\\\\", "/");
                            p++;
                            i3 = 1;
                        }
                        this.descent = 0.0f;
                        while (true) {
                            String line6 = reader3.readLine();
                            if (line6 == null || line6.startsWith("kernings ") || line6.startsWith("metrics ")) {
                                break;
                            }
                            BufferedReader reader4 = reader3;
                            String[] padding2 = padding;
                            String[] common2 = common;
                            int pageCount2 = pageCount;
                            if (line6.startsWith("char ")) {
                                Glyph glyph = new Glyph();
                                StringTokenizer tokens = new StringTokenizer(line6, " =");
                                tokens.nextToken();
                                tokens.nextToken();
                                int ch = Integer.parseInt(tokens.nextToken());
                                if (ch <= 0) {
                                    this.missingGlyph = glyph;
                                } else if (ch <= 65535) {
                                    setGlyph(ch, glyph);
                                }
                                glyph.id = ch;
                                tokens.nextToken();
                                glyph.srcX = Integer.parseInt(tokens.nextToken());
                                tokens.nextToken();
                                glyph.srcY = Integer.parseInt(tokens.nextToken());
                                tokens.nextToken();
                                glyph.width = Integer.parseInt(tokens.nextToken());
                                tokens.nextToken();
                                glyph.height = Integer.parseInt(tokens.nextToken());
                                tokens.nextToken();
                                glyph.xoffset = Integer.parseInt(tokens.nextToken());
                                tokens.nextToken();
                                if (flip) {
                                    glyph.yoffset = Integer.parseInt(tokens.nextToken());
                                } else {
                                    glyph.yoffset = -(glyph.height + Integer.parseInt(tokens.nextToken()));
                                }
                                tokens.nextToken();
                                glyph.xadvance = Integer.parseInt(tokens.nextToken());
                                if (tokens.hasMoreTokens()) {
                                    tokens.nextToken();
                                }
                                if (tokens.hasMoreTokens()) {
                                    try {
                                        glyph.page = Integer.parseInt(tokens.nextToken());
                                    } catch (NumberFormatException e3) {
                                    }
                                }
                                if (glyph.width > 0 && glyph.height > 0) {
                                    this.descent = Math.min(glyph.yoffset + baseLine, this.descent);
                                }
                            }
                            padding = padding2;
                            common = common2;
                            pageCount = pageCount2;
                            reader3 = reader4;
                        }
                        this.descent += this.padBottom;
                        while (true) {
                            line = reader3.readLine();
                            if (line == null || !line.startsWith("kerning ")) {
                                break;
                            }
                            BufferedReader reader5 = reader3;
                            String[] padding3 = padding;
                            String[] common3 = common;
                            int pageCount3 = pageCount;
                            StringTokenizer tokens2 = new StringTokenizer(line, " =");
                            tokens2.nextToken();
                            tokens2.nextToken();
                            int first = Integer.parseInt(tokens2.nextToken());
                            tokens2.nextToken();
                            int second = Integer.parseInt(tokens2.nextToken());
                            if (first >= 0 && first <= 65535 && second >= 0 && second <= 65535) {
                                Glyph glyph2 = getGlyph((char) first);
                                tokens2.nextToken();
                                int amount = Integer.parseInt(tokens2.nextToken());
                                if (glyph2 != null) {
                                    glyph2.setKerning(second, amount);
                                }
                            }
                            padding = padding3;
                            common = common3;
                            pageCount = pageCount3;
                            reader3 = reader5;
                        }
                        boolean hasMetricsOverride = false;
                        float overrideAscent = 0.0f;
                        float overrideDescent = 0.0f;
                        float overrideDown = 0.0f;
                        float overrideCapHeight = 0.0f;
                        if (line == null || !line.startsWith("metrics ")) {
                            overrideLineHeight = 0.0f;
                            overrideSpaceXAdvance = 0.0f;
                            overrideXHeight = 0.0f;
                        } else {
                            hasMetricsOverride = true;
                            StringTokenizer tokens3 = new StringTokenizer(line, " =");
                            tokens3.nextToken();
                            tokens3.nextToken();
                            overrideAscent = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            overrideDescent = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            overrideDown = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            overrideCapHeight = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            float overrideLineHeight2 = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            float overrideSpaceXAdvance5 = Float.parseFloat(tokens3.nextToken());
                            tokens3.nextToken();
                            float overrideXHeight4 = Float.parseFloat(tokens3.nextToken());
                            overrideLineHeight = overrideLineHeight2;
                            overrideSpaceXAdvance = overrideSpaceXAdvance5;
                            overrideXHeight = overrideXHeight4;
                        }
                        Glyph spaceGlyph = getGlyph(' ');
                        if (spaceGlyph == null) {
                            spaceGlyph = new Glyph();
                            spaceGlyph.id = 32;
                            Glyph xadvanceGlyph = getGlyph('l');
                            if (xadvanceGlyph == null) {
                                xadvanceGlyph = getFirstGlyph();
                            }
                            spaceGlyph.xadvance = xadvanceGlyph.xadvance;
                            setGlyph(32, spaceGlyph);
                        }
                        if (spaceGlyph.width == 0) {
                            spaceGlyph.width = (int) (this.padLeft + spaceGlyph.xadvance + this.padRight);
                            spaceGlyph.xoffset = (int) (-this.padLeft);
                        }
                        this.spaceXadvance = spaceGlyph.xadvance;
                        char[] cArr = this.xChars;
                        Glyph xGlyph = null;
                        int length = cArr.length;
                        int i4 = 0;
                        while (i4 < length) {
                            char xChar = cArr[i4];
                            int i5 = length;
                            xGlyph = getGlyph(xChar);
                            if (xGlyph != null) {
                                break;
                            }
                            i4++;
                            length = i5;
                        }
                        this.xHeight = (xGlyph == null ? getFirstGlyph() : xGlyph).height - padY;
                        char[] cArr2 = this.capChars;
                        int length2 = cArr2.length;
                        Glyph capGlyph2 = null;
                        int i6 = 0;
                        while (true) {
                            if (i6 >= length2) {
                                capGlyph = capGlyph2;
                                break;
                            }
                            char capChar = cArr2[i6];
                            int i7 = length2;
                            capGlyph2 = getGlyph(capChar);
                            if (capGlyph2 != null) {
                                capGlyph = capGlyph2;
                                break;
                            } else {
                                i6++;
                                length2 = i7;
                            }
                        }
                        if (capGlyph == null) {
                            Glyph[][] glyphArr = this.glyphs;
                            int length3 = glyphArr.length;
                            reader2 = reader3;
                            int i8 = 0;
                            while (i8 < length3) {
                                Glyph[][] glyphArr2 = glyphArr;
                                Glyph[] page = glyphArr[i8];
                                if (page == null) {
                                    overrideXHeight3 = overrideXHeight;
                                    overrideSpaceXAdvance3 = overrideSpaceXAdvance;
                                    i = length3;
                                } else {
                                    i = length3;
                                    int length4 = page.length;
                                    overrideXHeight3 = overrideXHeight;
                                    int i9 = 0;
                                    while (i9 < length4) {
                                        Glyph glyph3 = page[i9];
                                        Glyph[] page2 = page;
                                        if (glyph3 != null) {
                                            i2 = length4;
                                            if (glyph3.height == 0) {
                                                overrideSpaceXAdvance4 = overrideSpaceXAdvance;
                                            } else if (glyph3.width == 0) {
                                                overrideSpaceXAdvance4 = overrideSpaceXAdvance;
                                            } else {
                                                overrideSpaceXAdvance4 = overrideSpaceXAdvance;
                                                this.capHeight = Math.max(this.capHeight, glyph3.height);
                                            }
                                        } else {
                                            overrideSpaceXAdvance4 = overrideSpaceXAdvance;
                                            i2 = length4;
                                        }
                                        i9++;
                                        page = page2;
                                        length4 = i2;
                                        overrideSpaceXAdvance = overrideSpaceXAdvance4;
                                    }
                                    overrideSpaceXAdvance3 = overrideSpaceXAdvance;
                                }
                                i8++;
                                glyphArr = glyphArr2;
                                length3 = i;
                                overrideXHeight = overrideXHeight3;
                                overrideSpaceXAdvance = overrideSpaceXAdvance3;
                            }
                            overrideXHeight2 = overrideXHeight;
                            overrideSpaceXAdvance2 = overrideSpaceXAdvance;
                        } else {
                            reader2 = reader3;
                            overrideXHeight2 = overrideXHeight;
                            overrideSpaceXAdvance2 = overrideSpaceXAdvance;
                            this.capHeight = capGlyph.height;
                        }
                        this.capHeight -= padY;
                        this.ascent = baseLine - this.capHeight;
                        this.down = -this.lineHeight;
                        if (flip) {
                            this.ascent = -this.ascent;
                            this.down = -this.down;
                        }
                        if (hasMetricsOverride) {
                            this.ascent = overrideAscent;
                            this.descent = overrideDescent;
                            this.down = overrideDown;
                            this.capHeight = overrideCapHeight;
                            this.lineHeight = overrideLineHeight;
                            this.spaceXadvance = overrideSpaceXAdvance2;
                            this.xHeight = overrideXHeight2;
                        }
                        StreamUtils.closeQuietly(reader2);
                    } catch (Exception e4) {
                        ex = e4;
                    }
                } catch (Exception e5) {
                    reader = reader3;
                    ex = e5;
                } catch (Throwable th4) {
                    reader = reader3;
                    th = th4;
                }
            } catch (Throwable th5) {
                th = th5;
            }
        }

        public void setGlyphRegion(Glyph glyph, TextureRegion region) {
            Texture texture = region.getTexture();
            float invTexWidth = 1.0f / texture.getWidth();
            float invTexHeight = 1.0f / texture.getHeight();
            float offsetX = 0.0f;
            float offsetY = 0.0f;
            float u = region.u;
            float v = region.v;
            float regionWidth = region.getRegionWidth();
            float regionHeight = region.getRegionHeight();
            if (region instanceof TextureAtlas.AtlasRegion) {
                TextureAtlas.AtlasRegion atlasRegion = (TextureAtlas.AtlasRegion) region;
                offsetX = atlasRegion.offsetX;
                offsetY = (atlasRegion.originalHeight - atlasRegion.packedHeight) - atlasRegion.offsetY;
            }
            float x = glyph.srcX;
            float x2 = glyph.srcX + glyph.width;
            float y = glyph.srcY;
            float y2 = glyph.srcY + glyph.height;
            if (offsetX > 0.0f) {
                x -= offsetX;
                if (x < 0.0f) {
                    glyph.width = (int) (glyph.width + x);
                    glyph.xoffset = (int) (glyph.xoffset - x);
                    x = 0.0f;
                }
                x2 -= offsetX;
                if (x2 > regionWidth) {
                    glyph.width = (int) (glyph.width - (x2 - regionWidth));
                    x2 = regionWidth;
                }
            }
            if (offsetY > 0.0f) {
                y -= offsetY;
                if (y < 0.0f) {
                    glyph.height = (int) (glyph.height + y);
                    if (glyph.height < 0) {
                        glyph.height = 0;
                    }
                    y = 0.0f;
                }
                y2 -= offsetY;
                if (y2 > regionHeight) {
                    float amount = y2 - regionHeight;
                    glyph.height = (int) (glyph.height - amount);
                    glyph.yoffset = (int) (glyph.yoffset + amount);
                    y2 = regionHeight;
                }
            }
            glyph.u = (x * invTexWidth) + u;
            glyph.u2 = (x2 * invTexWidth) + u;
            if (this.flipped) {
                glyph.v = (y * invTexHeight) + v;
                glyph.v2 = (y2 * invTexHeight) + v;
                return;
            }
            glyph.v2 = (y * invTexHeight) + v;
            glyph.v = (y2 * invTexHeight) + v;
        }

        public void setLineHeight(float height) {
            this.lineHeight = this.scaleY * height;
            this.down = this.flipped ? this.lineHeight : -this.lineHeight;
        }

        public void setGlyph(int ch, Glyph glyph) {
            Glyph[][] glyphArr = this.glyphs;
            Glyph[] page = glyphArr[ch / 512];
            if (page == null) {
                Glyph[] glyphArr2 = new Glyph[512];
                page = glyphArr2;
                glyphArr[ch / 512] = glyphArr2;
            }
            page[ch & 511] = glyph;
        }

        public Glyph getFirstGlyph() {
            Glyph[][] glyphArr;
            for (Glyph[] page : this.glyphs) {
                if (page != null) {
                    for (Glyph glyph : page) {
                        if (glyph != null && glyph.height != 0 && glyph.width != 0) {
                            return glyph;
                        }
                    }
                    continue;
                }
            }
            throw new GdxRuntimeException("No glyphs found.");
        }

        public boolean hasGlyph(char ch) {
            return (this.missingGlyph == null && getGlyph(ch) == null) ? false : true;
        }

        public Glyph getGlyph(char ch) {
            Glyph[] page = this.glyphs[ch / 512];
            if (page != null) {
                return page[ch & 511];
            }
            return null;
        }

        public void getGlyphs(GlyphLayout.GlyphRun run, CharSequence str, int start, int end, Glyph lastGlyph) {
            float kerning;
            int max = end - start;
            if (max == 0) {
                return;
            }
            boolean markupEnabled = this.markupEnabled;
            float scaleX = this.scaleX;
            Array<Glyph> glyphs = run.glyphs;
            FloatArray xAdvances = run.xAdvances;
            glyphs.ensureCapacity(max);
            run.xAdvances.ensureCapacity(max + 1);
            do {
                int start2 = start + 1;
                char ch = str.charAt(start);
                if (ch != '\r') {
                    Glyph glyph = getGlyph(ch);
                    if (glyph == null) {
                        if (this.missingGlyph != null) {
                            glyph = this.missingGlyph;
                        }
                    }
                    glyphs.add(glyph);
                    if (lastGlyph == null) {
                        kerning = glyph.fixedWidth ? 0.0f : ((-glyph.xoffset) * scaleX) - this.padLeft;
                    } else {
                        kerning = (lastGlyph.xadvance + lastGlyph.getKerning(ch)) * scaleX;
                    }
                    xAdvances.add(kerning);
                    lastGlyph = glyph;
                    if (markupEnabled && ch == '[' && start2 < end && str.charAt(start2) == '[') {
                        start = start2 + 1;
                        continue;
                    }
                }
                start = start2;
                continue;
            } while (start < end);
            if (lastGlyph != null) {
                float lastGlyphWidth = lastGlyph.fixedWidth ? lastGlyph.xadvance * scaleX : ((lastGlyph.width + lastGlyph.xoffset) * scaleX) - this.padRight;
                xAdvances.add(lastGlyphWidth);
            }
        }

        public int getWrapIndex(Array<Glyph> glyphs, int start) {
            int i = start - 1;
            Object[] glyphsItems = glyphs.items;
            char ch = (char) ((Glyph) glyphsItems[i]).id;
            if (isWhitespace(ch)) {
                return i;
            }
            if (isBreakChar(ch)) {
                i--;
            }
            while (i > 0) {
                char ch2 = (char) ((Glyph) glyphsItems[i]).id;
                if (!isWhitespace(ch2) && !isBreakChar(ch2)) {
                    i--;
                } else {
                    return i + 1;
                }
            }
            return 0;
        }

        public boolean isBreakChar(char c) {
            char[] cArr = this.breakChars;
            if (cArr == null) {
                return false;
            }
            for (char br : cArr) {
                if (c == br) {
                    return true;
                }
            }
            return false;
        }

        public boolean isWhitespace(char c) {
            if (c == '\t' || c == '\n' || c == '\r' || c == ' ') {
                return true;
            }
            return false;
        }

        public String getImagePath(int index) {
            return this.imagePaths[index];
        }

        public String[] getImagePaths() {
            return this.imagePaths;
        }

        public FileHandle getFontFile() {
            return this.fontFile;
        }

        public void setScale(float scaleX, float scaleY) {
            if (scaleX == 0.0f) {
                throw new IllegalArgumentException("scaleX cannot be 0.");
            }
            if (scaleY == 0.0f) {
                throw new IllegalArgumentException("scaleY cannot be 0.");
            }
            float x = scaleX / this.scaleX;
            float y = scaleY / this.scaleY;
            this.lineHeight *= y;
            this.spaceXadvance *= x;
            this.xHeight *= y;
            this.capHeight *= y;
            this.ascent *= y;
            this.descent *= y;
            this.down *= y;
            this.padLeft *= x;
            this.padRight *= x;
            this.padTop *= y;
            this.padBottom *= y;
            this.scaleX = scaleX;
            this.scaleY = scaleY;
        }

        public void setScale(float scaleXY) {
            setScale(scaleXY, scaleXY);
        }

        public void scale(float amount) {
            setScale(this.scaleX + amount, this.scaleY + amount);
        }

        public String toString() {
            String str = this.name;
            return str != null ? str : super.toString();
        }
    }
}