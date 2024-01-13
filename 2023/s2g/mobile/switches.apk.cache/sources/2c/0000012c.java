package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.glutils.PixmapTextureData;
import com.badlogic.gdx.math.Rectangle;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.OrderedMap;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public class PixmapPacker implements Disposable {
    static Pattern indexPattern = Pattern.compile("(.+)_(\\d+)$");
    int alphaThreshold;
    private Color c;
    boolean disposed;
    boolean duplicateBorder;
    PackStrategy packStrategy;
    boolean packToTexture;
    int padding;
    Pixmap.Format pageFormat;
    int pageHeight;
    int pageWidth;
    final Array<Page> pages;
    boolean stripWhitespaceX;
    boolean stripWhitespaceY;
    Color transparentColor;

    /* loaded from: classes.dex */
    public interface PackStrategy {
        Page pack(PixmapPacker pixmapPacker, String str, Rectangle rectangle);

        void sort(Array<Pixmap> array);
    }

    public PixmapPacker(int pageWidth, int pageHeight, Pixmap.Format pageFormat, int padding, boolean duplicateBorder) {
        this(pageWidth, pageHeight, pageFormat, padding, duplicateBorder, false, false, new GuillotineStrategy());
    }

    public PixmapPacker(int pageWidth, int pageHeight, Pixmap.Format pageFormat, int padding, boolean duplicateBorder, PackStrategy packStrategy) {
        this(pageWidth, pageHeight, pageFormat, padding, duplicateBorder, false, false, packStrategy);
    }

    public PixmapPacker(int pageWidth, int pageHeight, Pixmap.Format pageFormat, int padding, boolean duplicateBorder, boolean stripWhitespaceX, boolean stripWhitespaceY, PackStrategy packStrategy) {
        this.transparentColor = new Color(0.0f, 0.0f, 0.0f, 0.0f);
        this.pages = new Array<>();
        this.c = new Color();
        this.pageWidth = pageWidth;
        this.pageHeight = pageHeight;
        this.pageFormat = pageFormat;
        this.padding = padding;
        this.duplicateBorder = duplicateBorder;
        this.stripWhitespaceX = stripWhitespaceX;
        this.stripWhitespaceY = stripWhitespaceY;
        this.packStrategy = packStrategy;
    }

    public void sort(Array<Pixmap> images) {
        this.packStrategy.sort(images);
    }

    public synchronized Rectangle pack(Pixmap image) {
        return pack(null, image);
    }

    /* JADX WARN: Code restructure failed: missing block: B:105:0x02cd, code lost:
        throw new com.badlogic.gdx.utils.GdxRuntimeException("Page size too small for pixmap.");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public synchronized com.badlogic.gdx.math.Rectangle pack(java.lang.String r36, com.badlogic.gdx.graphics.Pixmap r37) {
        /*
            Method dump skipped, instructions count: 746
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.graphics.g2d.PixmapPacker.pack(java.lang.String, com.badlogic.gdx.graphics.Pixmap):com.badlogic.gdx.math.Rectangle");
    }

    public Array<Page> getPages() {
        return this.pages;
    }

    public synchronized Rectangle getRect(String name) {
        Array.ArrayIterator<Page> it = this.pages.iterator();
        while (it.hasNext()) {
            Page page = it.next();
            Rectangle rect = page.rects.get(name);
            if (rect != null) {
                return rect;
            }
        }
        return null;
    }

    public synchronized Page getPage(String name) {
        Array.ArrayIterator<Page> it = this.pages.iterator();
        while (it.hasNext()) {
            Page page = it.next();
            Rectangle rect = page.rects.get(name);
            if (rect != null) {
                return page;
            }
        }
        return null;
    }

    public synchronized int getPageIndex(String name) {
        for (int i = 0; i < this.pages.size; i++) {
            Rectangle rect = this.pages.get(i).rects.get(name);
            if (rect != null) {
                return i;
            }
        }
        return -1;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public synchronized void dispose() {
        Array.ArrayIterator<Page> it = this.pages.iterator();
        while (it.hasNext()) {
            Page page = it.next();
            if (page.texture == null) {
                page.image.dispose();
            }
        }
        this.disposed = true;
    }

    public synchronized TextureAtlas generateTextureAtlas(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps) {
        TextureAtlas atlas;
        atlas = new TextureAtlas();
        updateTextureAtlas(atlas, minFilter, magFilter, useMipMaps);
        return atlas;
    }

    public synchronized void updateTextureAtlas(TextureAtlas atlas, Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps) {
        updateTextureAtlas(atlas, minFilter, magFilter, useMipMaps, true);
    }

    public synchronized void updateTextureAtlas(TextureAtlas atlas, Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps, boolean useIndexes) {
        updatePageTextures(minFilter, magFilter, useMipMaps);
        Array.ArrayIterator<Page> it = this.pages.iterator();
        while (it.hasNext()) {
            Page page = it.next();
            if (page.addedRects.size > 0) {
                Array.ArrayIterator<String> it2 = page.addedRects.iterator();
                while (it2.hasNext()) {
                    String name = it2.next();
                    PixmapPackerRectangle rect = page.rects.get(name);
                    TextureAtlas.AtlasRegion region = new TextureAtlas.AtlasRegion(page.texture, (int) rect.x, (int) rect.y, (int) rect.width, (int) rect.height);
                    if (rect.splits != null) {
                        region.names = new String[]{"split", "pad"};
                        region.values = new int[][]{rect.splits, rect.pads};
                    }
                    int imageIndex = -1;
                    String imageName = name;
                    if (useIndexes) {
                        Matcher matcher = indexPattern.matcher(imageName);
                        if (matcher.matches()) {
                            imageName = matcher.group(1);
                            imageIndex = Integer.parseInt(matcher.group(2));
                        }
                    }
                    region.name = imageName;
                    region.index = imageIndex;
                    region.offsetX = rect.offsetX;
                    region.offsetY = (int) ((rect.originalHeight - rect.height) - rect.offsetY);
                    region.originalWidth = rect.originalWidth;
                    region.originalHeight = rect.originalHeight;
                    atlas.getRegions().add(region);
                }
                page.addedRects.clear();
                atlas.getTextures().add(page.texture);
            }
        }
    }

    public synchronized void updateTextureRegions(Array<TextureRegion> regions, Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps) {
        updatePageTextures(minFilter, magFilter, useMipMaps);
        while (regions.size < this.pages.size) {
            regions.add(new TextureRegion(this.pages.get(regions.size).texture));
        }
    }

    public synchronized void updatePageTextures(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps) {
        Array.ArrayIterator<Page> it = this.pages.iterator();
        while (it.hasNext()) {
            Page page = it.next();
            page.updateTexture(minFilter, magFilter, useMipMaps);
        }
    }

    public int getPageWidth() {
        return this.pageWidth;
    }

    public void setPageWidth(int pageWidth) {
        this.pageWidth = pageWidth;
    }

    public int getPageHeight() {
        return this.pageHeight;
    }

    public void setPageHeight(int pageHeight) {
        this.pageHeight = pageHeight;
    }

    public Pixmap.Format getPageFormat() {
        return this.pageFormat;
    }

    public void setPageFormat(Pixmap.Format pageFormat) {
        this.pageFormat = pageFormat;
    }

    public int getPadding() {
        return this.padding;
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public boolean getDuplicateBorder() {
        return this.duplicateBorder;
    }

    public void setDuplicateBorder(boolean duplicateBorder) {
        this.duplicateBorder = duplicateBorder;
    }

    public boolean getPackToTexture() {
        return this.packToTexture;
    }

    public void setPackToTexture(boolean packToTexture) {
        this.packToTexture = packToTexture;
    }

    /* loaded from: classes.dex */
    public static class Page {
        boolean dirty;
        Pixmap image;
        Texture texture;
        OrderedMap<String, PixmapPackerRectangle> rects = new OrderedMap<>();
        final Array<String> addedRects = new Array<>();

        public Page(PixmapPacker packer) {
            this.image = new Pixmap(packer.pageWidth, packer.pageHeight, packer.pageFormat);
            this.image.setBlending(Pixmap.Blending.None);
            this.image.setColor(packer.getTransparentColor());
            this.image.fill();
        }

        public Pixmap getPixmap() {
            return this.image;
        }

        public OrderedMap<String, PixmapPackerRectangle> getRects() {
            return this.rects;
        }

        public Texture getTexture() {
            return this.texture;
        }

        public boolean updateTexture(Texture.TextureFilter minFilter, Texture.TextureFilter magFilter, boolean useMipMaps) {
            Texture texture = this.texture;
            if (texture != null) {
                if (!this.dirty) {
                    return false;
                }
                texture.load(texture.getTextureData());
            } else {
                Pixmap pixmap = this.image;
                this.texture = new Texture(new PixmapTextureData(pixmap, pixmap.getFormat(), useMipMaps, false, true)) { // from class: com.badlogic.gdx.graphics.g2d.PixmapPacker.Page.1
                    @Override // com.badlogic.gdx.graphics.Texture, com.badlogic.gdx.graphics.GLTexture, com.badlogic.gdx.utils.Disposable
                    public void dispose() {
                        super.dispose();
                        Page.this.image.dispose();
                    }
                };
                this.texture.setFilter(minFilter, magFilter);
            }
            this.dirty = false;
            return true;
        }
    }

    /* loaded from: classes.dex */
    public static class GuillotineStrategy implements PackStrategy {
        Comparator<Pixmap> comparator;

        @Override // com.badlogic.gdx.graphics.g2d.PixmapPacker.PackStrategy
        public void sort(Array<Pixmap> pixmaps) {
            if (this.comparator == null) {
                this.comparator = new Comparator<Pixmap>() { // from class: com.badlogic.gdx.graphics.g2d.PixmapPacker.GuillotineStrategy.1
                    @Override // java.util.Comparator
                    public int compare(Pixmap o1, Pixmap o2) {
                        return Math.max(o1.getWidth(), o1.getHeight()) - Math.max(o2.getWidth(), o2.getHeight());
                    }
                };
            }
            pixmaps.sort(this.comparator);
        }

        @Override // com.badlogic.gdx.graphics.g2d.PixmapPacker.PackStrategy
        public Page pack(PixmapPacker packer, String name, Rectangle rect) {
            GuillotinePage page;
            if (packer.pages.size == 0) {
                page = new GuillotinePage(packer);
                packer.pages.add(page);
            } else {
                page = (GuillotinePage) packer.pages.peek();
            }
            int padding = packer.padding;
            rect.width += padding;
            rect.height += padding;
            Node node = insert(page.root, rect);
            if (node == null) {
                page = new GuillotinePage(packer);
                packer.pages.add(page);
                node = insert(page.root, rect);
            }
            node.full = true;
            rect.set(node.rect.x, node.rect.y, node.rect.width - padding, node.rect.height - padding);
            return page;
        }

        private Node insert(Node node, Rectangle rect) {
            if (!node.full && node.leftChild != null && node.rightChild != null) {
                Node newNode = insert(node.leftChild, rect);
                return newNode == null ? insert(node.rightChild, rect) : newNode;
            } else if (node.full) {
                return null;
            } else {
                if (node.rect.width == rect.width && node.rect.height == rect.height) {
                    return node;
                }
                if (node.rect.width < rect.width || node.rect.height < rect.height) {
                    return null;
                }
                node.leftChild = new Node();
                node.rightChild = new Node();
                int deltaWidth = ((int) node.rect.width) - ((int) rect.width);
                int deltaHeight = ((int) node.rect.height) - ((int) rect.height);
                if (deltaWidth > deltaHeight) {
                    node.leftChild.rect.x = node.rect.x;
                    node.leftChild.rect.y = node.rect.y;
                    node.leftChild.rect.width = rect.width;
                    node.leftChild.rect.height = node.rect.height;
                    node.rightChild.rect.x = node.rect.x + rect.width;
                    node.rightChild.rect.y = node.rect.y;
                    node.rightChild.rect.width = node.rect.width - rect.width;
                    node.rightChild.rect.height = node.rect.height;
                } else {
                    node.leftChild.rect.x = node.rect.x;
                    node.leftChild.rect.y = node.rect.y;
                    node.leftChild.rect.width = node.rect.width;
                    node.leftChild.rect.height = rect.height;
                    node.rightChild.rect.x = node.rect.x;
                    node.rightChild.rect.y = node.rect.y + rect.height;
                    node.rightChild.rect.width = node.rect.width;
                    node.rightChild.rect.height = node.rect.height - rect.height;
                }
                return insert(node.leftChild, rect);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: classes.dex */
        public static final class Node {
            public boolean full;
            public Node leftChild;
            public final Rectangle rect = new Rectangle();
            public Node rightChild;

            Node() {
            }
        }

        /* loaded from: classes.dex */
        static class GuillotinePage extends Page {
            Node root;

            public GuillotinePage(PixmapPacker packer) {
                super(packer);
                this.root = new Node();
                this.root.rect.x = packer.padding;
                this.root.rect.y = packer.padding;
                this.root.rect.width = packer.pageWidth - (packer.padding * 2);
                this.root.rect.height = packer.pageHeight - (packer.padding * 2);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class SkylineStrategy implements PackStrategy {
        Comparator<Pixmap> comparator;

        @Override // com.badlogic.gdx.graphics.g2d.PixmapPacker.PackStrategy
        public void sort(Array<Pixmap> images) {
            if (this.comparator == null) {
                this.comparator = new Comparator<Pixmap>() { // from class: com.badlogic.gdx.graphics.g2d.PixmapPacker.SkylineStrategy.1
                    @Override // java.util.Comparator
                    public int compare(Pixmap o1, Pixmap o2) {
                        return o1.getHeight() - o2.getHeight();
                    }
                };
            }
            images.sort(this.comparator);
        }

        @Override // com.badlogic.gdx.graphics.g2d.PixmapPacker.PackStrategy
        public Page pack(PixmapPacker packer, String name, Rectangle rect) {
            int padding = packer.padding;
            int pageWidth = packer.pageWidth - (padding * 2);
            int pageHeight = packer.pageHeight - (padding * 2);
            int rectWidth = ((int) rect.width) + padding;
            int rectHeight = ((int) rect.height) + padding;
            int n = packer.pages.size;
            for (int i = 0; i < n; i++) {
                SkylinePage page = (SkylinePage) packer.pages.get(i);
                SkylinePage.Row bestRow = null;
                int nn = page.rows.size - 1;
                for (int ii = 0; ii < nn; ii++) {
                    SkylinePage.Row row = page.rows.get(ii);
                    if (row.x + rectWidth < pageWidth && row.y + rectHeight < pageHeight && rectHeight <= row.height && (bestRow == null || row.height < bestRow.height)) {
                        bestRow = row;
                    }
                }
                if (bestRow == null) {
                    SkylinePage.Row row2 = page.rows.peek();
                    if (row2.y + rectHeight >= pageHeight) {
                        continue;
                    } else if (row2.x + rectWidth < pageWidth) {
                        row2.height = Math.max(row2.height, rectHeight);
                        bestRow = row2;
                    } else if (row2.y + row2.height + rectHeight < pageHeight) {
                        bestRow = new SkylinePage.Row();
                        bestRow.y = row2.y + row2.height;
                        bestRow.height = rectHeight;
                        page.rows.add(bestRow);
                    }
                }
                if (bestRow != null) {
                    rect.x = bestRow.x;
                    rect.y = bestRow.y;
                    bestRow.x += rectWidth;
                    return page;
                }
            }
            SkylinePage page2 = new SkylinePage(packer);
            packer.pages.add(page2);
            SkylinePage.Row row3 = new SkylinePage.Row();
            row3.x = padding + rectWidth;
            row3.y = padding;
            row3.height = rectHeight;
            page2.rows.add(row3);
            rect.x = padding;
            rect.y = padding;
            return page2;
        }

        /* loaded from: classes.dex */
        static class SkylinePage extends Page {
            Array<Row> rows;

            public SkylinePage(PixmapPacker packer) {
                super(packer);
                this.rows = new Array<>();
            }

            /* loaded from: classes.dex */
            static class Row {
                int height;
                int x;
                int y;

                Row() {
                }
            }
        }
    }

    public Color getTransparentColor() {
        return this.transparentColor;
    }

    public void setTransparentColor(Color color) {
        this.transparentColor.set(color);
    }

    private int[] getSplits(Pixmap raster) {
        int endX;
        int endY;
        int startX = getSplitPoint(raster, 1, 0, true, true);
        int endX2 = getSplitPoint(raster, startX, 0, false, true);
        int startY = getSplitPoint(raster, 0, 1, true, false);
        int endY2 = getSplitPoint(raster, 0, startY, false, false);
        getSplitPoint(raster, endX2 + 1, 0, true, true);
        getSplitPoint(raster, 0, endY2 + 1, true, false);
        if (startX == 0 && endX2 == 0 && startY == 0 && endY2 == 0) {
            return null;
        }
        if (startX == 0) {
            endX = raster.getWidth() - 2;
        } else {
            startX--;
            endX = (raster.getWidth() - 2) - (endX2 - 1);
        }
        if (startY == 0) {
            endY = raster.getHeight() - 2;
        } else {
            startY--;
            endY = (raster.getHeight() - 2) - (endY2 - 1);
        }
        return new int[]{startX, endX, startY, endY};
    }

    private int[] getPads(Pixmap raster, int[] splits) {
        int endX;
        int endY;
        int bottom = raster.getHeight() - 1;
        int right = raster.getWidth() - 1;
        int startX = getSplitPoint(raster, 1, bottom, true, true);
        int startY = getSplitPoint(raster, right, 1, true, false);
        int endX2 = startX != 0 ? getSplitPoint(raster, startX + 1, bottom, false, true) : 0;
        int endY2 = startY != 0 ? getSplitPoint(raster, right, startY + 1, false, false) : 0;
        getSplitPoint(raster, endX2 + 1, bottom, true, true);
        getSplitPoint(raster, right, endY2 + 1, true, false);
        if (startX == 0 && endX2 == 0 && startY == 0 && endY2 == 0) {
            return null;
        }
        if (startX == 0 && endX2 == 0) {
            startX = -1;
            endX = -1;
        } else if (startX <= 0) {
            endX = raster.getWidth() - 2;
        } else {
            startX--;
            endX = (raster.getWidth() - 2) - (endX2 - 1);
        }
        if (startY == 0 && endY2 == 0) {
            startY = -1;
            endY = -1;
        } else if (startY <= 0) {
            endY = raster.getHeight() - 2;
        } else {
            startY--;
            endY = (raster.getHeight() - 2) - (endY2 - 1);
        }
        int[] pads = {startX, endX, startY, endY};
        if (splits == null || !Arrays.equals(pads, splits)) {
            return pads;
        }
        return null;
    }

    private int getSplitPoint(Pixmap raster, int startX, int startY, boolean startPoint, boolean xAxis) {
        int[] rgba = new int[4];
        int end = xAxis ? raster.getWidth() : raster.getHeight();
        int breakA = startPoint ? 255 : 0;
        int x = startX;
        int y = startY;
        for (int next = xAxis ? startX : startY; next != end; next++) {
            if (xAxis) {
                x = next;
            } else {
                y = next;
            }
            int colint = raster.getPixel(x, y);
            this.c.set(colint);
            rgba[0] = (int) (this.c.r * 255.0f);
            rgba[1] = (int) (this.c.g * 255.0f);
            rgba[2] = (int) (this.c.b * 255.0f);
            rgba[3] = (int) (this.c.a * 255.0f);
            if (rgba[3] == breakA) {
                return next;
            }
            if (!startPoint && (rgba[0] != 0 || rgba[1] != 0 || rgba[2] != 0 || rgba[3] != 255)) {
                PrintStream printStream = System.out;
                printStream.println(x + "  " + y + " " + rgba + " ");
            }
        }
        return 0;
    }

    /* loaded from: classes.dex */
    public static class PixmapPackerRectangle extends Rectangle {
        int offsetX;
        int offsetY;
        int originalHeight;
        int originalWidth;
        int[] pads;
        int[] splits;

        PixmapPackerRectangle(int x, int y, int width, int height) {
            super(x, y, width, height);
            this.offsetX = 0;
            this.offsetY = 0;
            this.originalWidth = width;
            this.originalHeight = height;
        }

        PixmapPackerRectangle(int x, int y, int width, int height, int left, int top, int originalWidth, int originalHeight) {
            super(x, y, width, height);
            this.offsetX = left;
            this.offsetY = top;
            this.originalWidth = originalWidth;
            this.originalHeight = originalHeight;
        }
    }
}