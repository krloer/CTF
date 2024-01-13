package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Pixmap;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Comparator;
import kotlin.jvm.internal.IntCompanionObject;

/* loaded from: classes.dex */
public class TextureAtlas implements Disposable {
    private final Array<AtlasRegion> regions;
    private final ObjectSet<Texture> textures;

    public TextureAtlas() {
        this.textures = new ObjectSet<>(4);
        this.regions = new Array<>();
    }

    public TextureAtlas(String internalPackFile) {
        this(Gdx.files.internal(internalPackFile));
    }

    public TextureAtlas(FileHandle packFile) {
        this(packFile, packFile.parent());
    }

    public TextureAtlas(FileHandle packFile, boolean flip) {
        this(packFile, packFile.parent(), flip);
    }

    public TextureAtlas(FileHandle packFile, FileHandle imagesDir) {
        this(packFile, imagesDir, false);
    }

    public TextureAtlas(FileHandle packFile, FileHandle imagesDir, boolean flip) {
        this(new TextureAtlasData(packFile, imagesDir, flip));
    }

    public TextureAtlas(TextureAtlasData data) {
        this.textures = new ObjectSet<>(4);
        this.regions = new Array<>();
        load(data);
    }

    public void load(TextureAtlasData data) {
        this.textures.ensureCapacity(data.pages.size);
        Array.ArrayIterator<TextureAtlasData.Page> it = data.pages.iterator();
        while (it.hasNext()) {
            TextureAtlasData.Page page = it.next();
            if (page.texture == null) {
                page.texture = new Texture(page.textureFile, page.format, page.useMipMaps);
            }
            page.texture.setFilter(page.minFilter, page.magFilter);
            page.texture.setWrap(page.uWrap, page.vWrap);
            this.textures.add(page.texture);
        }
        this.regions.ensureCapacity(data.regions.size);
        Array.ArrayIterator<TextureAtlasData.Region> it2 = data.regions.iterator();
        while (it2.hasNext()) {
            TextureAtlasData.Region region = it2.next();
            AtlasRegion atlasRegion = new AtlasRegion(region.page.texture, region.left, region.top, region.rotate ? region.height : region.width, region.rotate ? region.width : region.height);
            atlasRegion.index = region.index;
            atlasRegion.name = region.name;
            atlasRegion.offsetX = region.offsetX;
            atlasRegion.offsetY = region.offsetY;
            atlasRegion.originalHeight = region.originalHeight;
            atlasRegion.originalWidth = region.originalWidth;
            atlasRegion.rotate = region.rotate;
            atlasRegion.degrees = region.degrees;
            atlasRegion.names = region.names;
            atlasRegion.values = region.values;
            if (region.flip) {
                atlasRegion.flip(false, true);
            }
            this.regions.add(atlasRegion);
        }
    }

    public AtlasRegion addRegion(String name, Texture texture, int x, int y, int width, int height) {
        this.textures.add(texture);
        AtlasRegion region = new AtlasRegion(texture, x, y, width, height);
        region.name = name;
        this.regions.add(region);
        return region;
    }

    public AtlasRegion addRegion(String name, TextureRegion textureRegion) {
        this.textures.add(textureRegion.texture);
        AtlasRegion region = new AtlasRegion(textureRegion);
        region.name = name;
        this.regions.add(region);
        return region;
    }

    public Array<AtlasRegion> getRegions() {
        return this.regions;
    }

    public AtlasRegion findRegion(String name) {
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            if (this.regions.get(i).name.equals(name)) {
                return this.regions.get(i);
            }
        }
        return null;
    }

    public AtlasRegion findRegion(String name, int index) {
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            AtlasRegion region = this.regions.get(i);
            if (region.name.equals(name) && region.index == index) {
                return region;
            }
        }
        return null;
    }

    public Array<AtlasRegion> findRegions(String name) {
        Array<AtlasRegion> matched = new Array<>(AtlasRegion.class);
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            AtlasRegion region = this.regions.get(i);
            if (region.name.equals(name)) {
                matched.add(new AtlasRegion(region));
            }
        }
        return matched;
    }

    public Array<Sprite> createSprites() {
        Array sprites = new Array(true, this.regions.size, Sprite.class);
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            sprites.add(newSprite(this.regions.get(i)));
        }
        return sprites;
    }

    public Sprite createSprite(String name) {
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            if (this.regions.get(i).name.equals(name)) {
                return newSprite(this.regions.get(i));
            }
        }
        return null;
    }

    public Sprite createSprite(String name, int index) {
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            AtlasRegion region = this.regions.get(i);
            if (region.index == index && region.name.equals(name)) {
                return newSprite(this.regions.get(i));
            }
        }
        return null;
    }

    public Array<Sprite> createSprites(String name) {
        Array<Sprite> matched = new Array<>(Sprite.class);
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            AtlasRegion region = this.regions.get(i);
            if (region.name.equals(name)) {
                matched.add(newSprite(region));
            }
        }
        return matched;
    }

    private Sprite newSprite(AtlasRegion region) {
        if (region.packedWidth == region.originalWidth && region.packedHeight == region.originalHeight) {
            if (region.rotate) {
                Sprite sprite = new Sprite(region);
                sprite.setBounds(0.0f, 0.0f, region.getRegionHeight(), region.getRegionWidth());
                sprite.rotate90(true);
                return sprite;
            }
            return new Sprite(region);
        }
        return new AtlasSprite(region);
    }

    public NinePatch createPatch(String name) {
        int n = this.regions.size;
        for (int i = 0; i < n; i++) {
            AtlasRegion region = this.regions.get(i);
            if (region.name.equals(name)) {
                int[] splits = region.findValue("split");
                if (splits == null) {
                    throw new IllegalArgumentException("Region does not have ninepatch splits: " + name);
                }
                NinePatch patch = new NinePatch(region, splits[0], splits[1], splits[2], splits[3]);
                int[] pads = region.findValue("pad");
                if (pads != null) {
                    patch.setPadding(pads[0], pads[1], pads[2], pads[3]);
                }
                return patch;
            }
        }
        return null;
    }

    public ObjectSet<Texture> getTextures() {
        return this.textures;
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        ObjectSet.ObjectSetIterator<Texture> it = this.textures.iterator();
        while (it.hasNext()) {
            Texture texture = it.next();
            texture.dispose();
        }
        this.textures.clear(0);
    }

    /* loaded from: classes.dex */
    public static class TextureAtlasData {
        final Array<Page> pages = new Array<>();
        final Array<Region> regions = new Array<>();

        /* JADX INFO: Access modifiers changed from: private */
        /* loaded from: classes.dex */
        public interface Field<T> {
            void parse(T t);
        }

        /* loaded from: classes.dex */
        public static class Page {
            public float height;
            public boolean pma;
            public Texture texture;
            public FileHandle textureFile;
            public boolean useMipMaps;
            public float width;
            public Pixmap.Format format = Pixmap.Format.RGBA8888;
            public Texture.TextureFilter minFilter = Texture.TextureFilter.Nearest;
            public Texture.TextureFilter magFilter = Texture.TextureFilter.Nearest;
            public Texture.TextureWrap uWrap = Texture.TextureWrap.ClampToEdge;
            public Texture.TextureWrap vWrap = Texture.TextureWrap.ClampToEdge;
        }

        public TextureAtlasData() {
        }

        public TextureAtlasData(FileHandle packFile, FileHandle imagesDir, boolean flip) {
            load(packFile, imagesDir, flip);
        }

        public void load(FileHandle packFile, FileHandle imagesDir, boolean flip) {
            String line;
            int[] entryValues;
            TextureAtlasData textureAtlasData = this;
            final String[] entry = new String[5];
            ObjectMap<String, Field<Page>> pageFields = new ObjectMap<>(15, 0.99f);
            pageFields.put("size", new Field<Page>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.1
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Page page) {
                    page.width = Integer.parseInt(entry[1]);
                    page.height = Integer.parseInt(entry[2]);
                }
            });
            pageFields.put("format", new Field<Page>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.2
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Page page) {
                    page.format = Pixmap.Format.valueOf(entry[1]);
                }
            });
            pageFields.put("filter", new Field<Page>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.3
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Page page) {
                    page.minFilter = Texture.TextureFilter.valueOf(entry[1]);
                    page.magFilter = Texture.TextureFilter.valueOf(entry[2]);
                    page.useMipMaps = page.minFilter.isMipMap();
                }
            });
            pageFields.put("repeat", new Field<Page>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.4
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Page page) {
                    if (entry[1].indexOf(Input.Keys.PRINT_SCREEN) != -1) {
                        page.uWrap = Texture.TextureWrap.Repeat;
                    }
                    if (entry[1].indexOf(Input.Keys.PAUSE) != -1) {
                        page.vWrap = Texture.TextureWrap.Repeat;
                    }
                }
            });
            pageFields.put("pma", new Field<Page>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.5
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Page page) {
                    page.pma = entry[1].equals("true");
                }
            });
            boolean z = true;
            char c = 0;
            final boolean[] hasIndexes = {false};
            ObjectMap<String, Field<Region>> regionFields = new ObjectMap<>(127, 0.99f);
            regionFields.put("xy", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.6
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.left = Integer.parseInt(entry[1]);
                    region.top = Integer.parseInt(entry[2]);
                }
            });
            regionFields.put("size", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.7
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.width = Integer.parseInt(entry[1]);
                    region.height = Integer.parseInt(entry[2]);
                }
            });
            regionFields.put("bounds", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.8
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.left = Integer.parseInt(entry[1]);
                    region.top = Integer.parseInt(entry[2]);
                    region.width = Integer.parseInt(entry[3]);
                    region.height = Integer.parseInt(entry[4]);
                }
            });
            regionFields.put("offset", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.9
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.offsetX = Integer.parseInt(entry[1]);
                    region.offsetY = Integer.parseInt(entry[2]);
                }
            });
            regionFields.put("orig", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.10
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.originalWidth = Integer.parseInt(entry[1]);
                    region.originalHeight = Integer.parseInt(entry[2]);
                }
            });
            regionFields.put("offsets", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.11
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.offsetX = Integer.parseInt(entry[1]);
                    region.offsetY = Integer.parseInt(entry[2]);
                    region.originalWidth = Integer.parseInt(entry[3]);
                    region.originalHeight = Integer.parseInt(entry[4]);
                }
            });
            regionFields.put("rotate", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.12
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    String value = entry[1];
                    if (value.equals("true")) {
                        region.degrees = 90;
                    } else if (!value.equals("false")) {
                        region.degrees = Integer.parseInt(value);
                    }
                    region.rotate = region.degrees == 90;
                }
            });
            regionFields.put("index", new Field<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.13
                @Override // com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.Field
                public void parse(Region region) {
                    region.index = Integer.parseInt(entry[1]);
                    if (region.index != -1) {
                        hasIndexes[0] = true;
                    }
                }
            });
            BufferedReader reader = new BufferedReader(new InputStreamReader(packFile.read()), GL20.GL_STENCIL_BUFFER_BIT);
            try {
                try {
                    try {
                        String line2 = reader.readLine();
                        while (line2 != null) {
                            try {
                                if (line2.trim().length() != 0) {
                                    break;
                                }
                                line2 = reader.readLine();
                            } catch (Throwable th) {
                                ex = th;
                                StreamUtils.closeQuietly(reader);
                                throw ex;
                            }
                        }
                        while (line2 != null && line2.trim().length() != 0 && readEntry(entry, line2) != 0) {
                            line2 = reader.readLine();
                        }
                        Page page = null;
                        Array<Object> names = null;
                        Array<Object> values = null;
                        while (line2 != null) {
                            if (line2.trim().length() == 0) {
                                page = null;
                                line2 = reader.readLine();
                            } else if (page == null) {
                                page = new Page();
                                try {
                                    page.textureFile = imagesDir.child(line2);
                                    while (true) {
                                        String readLine = reader.readLine();
                                        line2 = readLine;
                                        if (readEntry(entry, readLine) == 0) {
                                            break;
                                        }
                                        Field field = pageFields.get(entry[c]);
                                        if (field != null) {
                                            field.parse(page);
                                        }
                                    }
                                    textureAtlasData.pages.add(page);
                                } catch (Exception e) {
                                    ex = e;
                                    StringBuilder sb = new StringBuilder();
                                    sb.append("Error reading texture atlas file: ");
                                    try {
                                        sb.append(packFile);
                                        throw new GdxRuntimeException(sb.toString(), ex);
                                    } catch (Throwable th2) {
                                        ex = th2;
                                        StreamUtils.closeQuietly(reader);
                                        throw ex;
                                    }
                                }
                            } else {
                                Region region = new Region();
                                region.page = page;
                                region.name = line2.trim();
                                if (flip) {
                                    region.flip = z;
                                }
                                while (true) {
                                    line = reader.readLine();
                                    int count = readEntry(entry, line);
                                    if (count == 0) {
                                        break;
                                    }
                                    Field field2 = regionFields.get(entry[c]);
                                    if (field2 != null) {
                                        field2.parse(region);
                                    } else {
                                        if (names == null) {
                                            names = new Array<>(8);
                                            values = new Array<>(8);
                                        }
                                        names.add(entry[0]);
                                        int[] entryValues2 = new int[count];
                                        int i = 0;
                                        while (i < count) {
                                            try {
                                                entryValues = entryValues2;
                                                try {
                                                    entryValues[i] = Integer.parseInt(entry[i + 1]);
                                                } catch (NumberFormatException e2) {
                                                }
                                            } catch (NumberFormatException e3) {
                                                entryValues = entryValues2;
                                            }
                                            i++;
                                            entryValues2 = entryValues;
                                        }
                                        values.add(entryValues2);
                                    }
                                    z = true;
                                    c = 0;
                                    textureAtlasData = this;
                                }
                                if (region.originalWidth == 0 && region.originalHeight == 0) {
                                    region.originalWidth = region.width;
                                    region.originalHeight = region.height;
                                }
                                if (names != null && names.size > 0) {
                                    region.names = (String[]) names.toArray(String.class);
                                    region.values = (int[][]) values.toArray(int[].class);
                                    names.clear();
                                    values.clear();
                                }
                                textureAtlasData.regions.add(region);
                                line2 = line;
                            }
                        }
                        StreamUtils.closeQuietly(reader);
                        if (hasIndexes[c]) {
                            textureAtlasData.regions.sort(new Comparator<Region>() { // from class: com.badlogic.gdx.graphics.g2d.TextureAtlas.TextureAtlasData.14
                                @Override // java.util.Comparator
                                public int compare(Region region1, Region region2) {
                                    int i1 = region1.index;
                                    if (i1 == -1) {
                                        i1 = IntCompanionObject.MAX_VALUE;
                                    }
                                    int i2 = region2.index;
                                    if (i2 == -1) {
                                        i2 = IntCompanionObject.MAX_VALUE;
                                    }
                                    return i1 - i2;
                                }
                            });
                        }
                    } catch (Throwable th3) {
                        ex = th3;
                        StreamUtils.closeQuietly(reader);
                        throw ex;
                    }
                } catch (Exception e4) {
                    ex = e4;
                }
            } catch (Throwable th4) {
                ex = th4;
                StreamUtils.closeQuietly(reader);
                throw ex;
            }
        }

        public Array<Page> getPages() {
            return this.pages;
        }

        public Array<Region> getRegions() {
            return this.regions;
        }

        private static int readEntry(String[] entry, String line) throws IOException {
            int colon;
            if (line == null) {
                return 0;
            }
            String line2 = line.trim();
            if (line2.length() != 0 && (colon = line2.indexOf(58)) != -1) {
                entry[0] = line2.substring(0, colon).trim();
                int i = 1;
                int lastMatch = colon + 1;
                while (true) {
                    int comma = line2.indexOf(44, lastMatch);
                    if (comma == -1) {
                        entry[i] = line2.substring(lastMatch).trim();
                        return i;
                    }
                    entry[i] = line2.substring(lastMatch, comma).trim();
                    lastMatch = comma + 1;
                    if (i != 4) {
                        i++;
                    } else {
                        return 4;
                    }
                }
            } else {
                return 0;
            }
        }

        /* loaded from: classes.dex */
        public static class Region {
            public int degrees;
            public boolean flip;
            public int height;
            public int index = -1;
            public int left;
            public String name;
            public String[] names;
            public float offsetX;
            public float offsetY;
            public int originalHeight;
            public int originalWidth;
            public Page page;
            public boolean rotate;
            public int top;
            public int[][] values;
            public int width;

            public int[] findValue(String name) {
                String[] strArr = this.names;
                if (strArr != null) {
                    int n = strArr.length;
                    for (int i = 0; i < n; i++) {
                        if (name.equals(this.names[i])) {
                            return this.values[i];
                        }
                    }
                    return null;
                }
                return null;
            }
        }
    }

    /* loaded from: classes.dex */
    public static class AtlasRegion extends TextureRegion {
        public int degrees;
        public int index;
        public String name;
        public String[] names;
        public float offsetX;
        public float offsetY;
        public int originalHeight;
        public int originalWidth;
        public int packedHeight;
        public int packedWidth;
        public boolean rotate;
        public int[][] values;

        public AtlasRegion(Texture texture, int x, int y, int width, int height) {
            super(texture, x, y, width, height);
            this.index = -1;
            this.originalWidth = width;
            this.originalHeight = height;
            this.packedWidth = width;
            this.packedHeight = height;
        }

        public AtlasRegion(AtlasRegion region) {
            this.index = -1;
            setRegion(region);
            this.index = region.index;
            this.name = region.name;
            this.offsetX = region.offsetX;
            this.offsetY = region.offsetY;
            this.packedWidth = region.packedWidth;
            this.packedHeight = region.packedHeight;
            this.originalWidth = region.originalWidth;
            this.originalHeight = region.originalHeight;
            this.rotate = region.rotate;
            this.degrees = region.degrees;
            this.names = region.names;
            this.values = region.values;
        }

        public AtlasRegion(TextureRegion region) {
            this.index = -1;
            setRegion(region);
            this.packedWidth = region.getRegionWidth();
            this.packedHeight = region.getRegionHeight();
            this.originalWidth = this.packedWidth;
            this.originalHeight = this.packedHeight;
        }

        @Override // com.badlogic.gdx.graphics.g2d.TextureRegion
        public void flip(boolean x, boolean y) {
            super.flip(x, y);
            if (x) {
                this.offsetX = (this.originalWidth - this.offsetX) - getRotatedPackedWidth();
            }
            if (y) {
                this.offsetY = (this.originalHeight - this.offsetY) - getRotatedPackedHeight();
            }
        }

        public float getRotatedPackedWidth() {
            return this.rotate ? this.packedHeight : this.packedWidth;
        }

        public float getRotatedPackedHeight() {
            return this.rotate ? this.packedWidth : this.packedHeight;
        }

        public int[] findValue(String name) {
            String[] strArr = this.names;
            if (strArr != null) {
                int n = strArr.length;
                for (int i = 0; i < n; i++) {
                    if (name.equals(this.names[i])) {
                        return this.values[i];
                    }
                }
                return null;
            }
            return null;
        }

        public String toString() {
            return this.name;
        }
    }

    /* loaded from: classes.dex */
    public static class AtlasSprite extends Sprite {
        float originalOffsetX;
        float originalOffsetY;
        final AtlasRegion region;

        public AtlasSprite(AtlasRegion region) {
            this.region = new AtlasRegion(region);
            this.originalOffsetX = region.offsetX;
            this.originalOffsetY = region.offsetY;
            setRegion(region);
            setOrigin(region.originalWidth / 2.0f, region.originalHeight / 2.0f);
            int width = region.getRegionWidth();
            int height = region.getRegionHeight();
            if (region.rotate) {
                super.rotate90(true);
                super.setBounds(region.offsetX, region.offsetY, height, width);
            } else {
                super.setBounds(region.offsetX, region.offsetY, width, height);
            }
            setColor(1.0f, 1.0f, 1.0f, 1.0f);
        }

        public AtlasSprite(AtlasSprite sprite) {
            this.region = sprite.region;
            this.originalOffsetX = sprite.originalOffsetX;
            this.originalOffsetY = sprite.originalOffsetY;
            set(sprite);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setPosition(float x, float y) {
            super.setPosition(this.region.offsetX + x, this.region.offsetY + y);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setX(float x) {
            super.setX(this.region.offsetX + x);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setY(float y) {
            super.setY(this.region.offsetY + y);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setBounds(float x, float y, float width, float height) {
            float widthRatio = width / this.region.originalWidth;
            float heightRatio = height / this.region.originalHeight;
            AtlasRegion atlasRegion = this.region;
            atlasRegion.offsetX = this.originalOffsetX * widthRatio;
            atlasRegion.offsetY = this.originalOffsetY * heightRatio;
            int packedWidth = atlasRegion.rotate ? this.region.packedHeight : this.region.packedWidth;
            int packedHeight = this.region.rotate ? this.region.packedWidth : this.region.packedHeight;
            super.setBounds(this.region.offsetX + x, this.region.offsetY + y, packedWidth * widthRatio, packedHeight * heightRatio);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setSize(float width, float height) {
            setBounds(getX(), getY(), width, height);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setOrigin(float originX, float originY) {
            super.setOrigin(originX - this.region.offsetX, originY - this.region.offsetY);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void setOriginCenter() {
            super.setOrigin((this.width / 2.0f) - this.region.offsetX, (this.height / 2.0f) - this.region.offsetY);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite, com.badlogic.gdx.graphics.g2d.TextureRegion
        public void flip(boolean x, boolean y) {
            if (this.region.rotate) {
                super.flip(y, x);
            } else {
                super.flip(x, y);
            }
            float oldOriginX = getOriginX();
            float oldOriginY = getOriginY();
            float oldOffsetX = this.region.offsetX;
            float oldOffsetY = this.region.offsetY;
            float widthRatio = getWidthRatio();
            float heightRatio = getHeightRatio();
            AtlasRegion atlasRegion = this.region;
            atlasRegion.offsetX = this.originalOffsetX;
            atlasRegion.offsetY = this.originalOffsetY;
            atlasRegion.flip(x, y);
            this.originalOffsetX = this.region.offsetX;
            this.originalOffsetY = this.region.offsetY;
            this.region.offsetX *= widthRatio;
            this.region.offsetY *= heightRatio;
            translate(this.region.offsetX - oldOffsetX, this.region.offsetY - oldOffsetY);
            setOrigin(oldOriginX, oldOriginY);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public void rotate90(boolean clockwise) {
            super.rotate90(clockwise);
            float oldOriginX = getOriginX();
            float oldOriginY = getOriginY();
            float oldOffsetX = this.region.offsetX;
            float oldOffsetY = this.region.offsetY;
            float widthRatio = getWidthRatio();
            float heightRatio = getHeightRatio();
            if (clockwise) {
                AtlasRegion atlasRegion = this.region;
                atlasRegion.offsetX = oldOffsetY;
                atlasRegion.offsetY = ((atlasRegion.originalHeight * heightRatio) - oldOffsetX) - (this.region.packedWidth * widthRatio);
            } else {
                AtlasRegion atlasRegion2 = this.region;
                atlasRegion2.offsetX = ((atlasRegion2.originalWidth * widthRatio) - oldOffsetY) - (this.region.packedHeight * heightRatio);
                this.region.offsetY = oldOffsetX;
            }
            translate(this.region.offsetX - oldOffsetX, this.region.offsetY - oldOffsetY);
            setOrigin(oldOriginX, oldOriginY);
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getX() {
            return super.getX() - this.region.offsetX;
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getY() {
            return super.getY() - this.region.offsetY;
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getOriginX() {
            return super.getOriginX() + this.region.offsetX;
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getOriginY() {
            return super.getOriginY() + this.region.offsetY;
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getWidth() {
            return (super.getWidth() / this.region.getRotatedPackedWidth()) * this.region.originalWidth;
        }

        @Override // com.badlogic.gdx.graphics.g2d.Sprite
        public float getHeight() {
            return (super.getHeight() / this.region.getRotatedPackedHeight()) * this.region.originalHeight;
        }

        public float getWidthRatio() {
            return super.getWidth() / this.region.getRotatedPackedWidth();
        }

        public float getHeightRatio() {
            return super.getHeight() / this.region.getRotatedPackedHeight();
        }

        public AtlasRegion getAtlasRegion() {
            return this.region;
        }

        public String toString() {
            return this.region.toString();
        }
    }
}