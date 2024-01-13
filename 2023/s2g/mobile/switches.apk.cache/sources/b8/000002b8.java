package com.badlogic.gdx.maps.tiled;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.ImageResolver;
import com.badlogic.gdx.maps.MapGroupLayer;
import com.badlogic.gdx.maps.MapLayer;
import com.badlogic.gdx.maps.MapLayers;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.BaseTmxMapLoader.Parameters;
import com.badlogic.gdx.maps.tiled.TiledMapTileLayer;
import com.badlogic.gdx.maps.tiled.tiles.AnimatedTiledMapTile;
import com.badlogic.gdx.maps.tiled.tiles.StaticTiledMapTile;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Base64Coder;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.IntArray;
import com.badlogic.gdx.utils.SerializationException;
import com.badlogic.gdx.utils.StreamUtils;
import com.badlogic.gdx.utils.XmlReader;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import kotlin.UByte;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public abstract class BaseTmxMapLoader<P extends Parameters> extends AsynchronousAssetLoader<TiledMap, P> {
    protected static final int FLAG_FLIP_DIAGONALLY = 536870912;
    protected static final int FLAG_FLIP_HORIZONTALLY = Integer.MIN_VALUE;
    protected static final int FLAG_FLIP_VERTICALLY = 1073741824;
    protected static final int MASK_CLEAR = -536870912;
    protected boolean convertObjectToTileSpace;
    protected boolean flipY;
    protected TiledMap map;
    protected int mapHeightInPixels;
    protected int mapTileHeight;
    protected int mapTileWidth;
    protected int mapWidthInPixels;
    protected XmlReader.Element root;
    protected XmlReader xml;

    /* loaded from: classes.dex */
    public static class Parameters extends AssetLoaderParameters<TiledMap> {
        public boolean generateMipMaps = false;
        public Texture.TextureFilter textureMinFilter = Texture.TextureFilter.Nearest;
        public Texture.TextureFilter textureMagFilter = Texture.TextureFilter.Nearest;
        public boolean convertObjectToTileSpace = false;
        public boolean flipY = true;
    }

    protected abstract void addStaticTiles(FileHandle fileHandle, ImageResolver imageResolver, TiledMapTileSet tiledMapTileSet, XmlReader.Element element, Array<XmlReader.Element> array, String str, int i, int i2, int i3, int i4, int i5, String str2, int i6, int i7, String str3, int i8, int i9, FileHandle fileHandle2);

    protected abstract Array<AssetDescriptor> getDependencyAssetDescriptors(FileHandle fileHandle, TextureLoader.TextureParameter textureParameter);

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public /* bridge */ /* synthetic */ Array getDependencies(String str, FileHandle fileHandle, AssetLoaderParameters assetLoaderParameters) {
        return getDependencies(str, fileHandle, (FileHandle) ((Parameters) assetLoaderParameters));
    }

    public BaseTmxMapLoader(FileHandleResolver resolver) {
        super(resolver);
        this.xml = new XmlReader();
        this.flipY = true;
    }

    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle tmxFile, P parameter) {
        this.root = this.xml.parse(tmxFile);
        TextureLoader.TextureParameter textureParameter = new TextureLoader.TextureParameter();
        if (parameter != null) {
            textureParameter.genMipMaps = parameter.generateMipMaps;
            textureParameter.minFilter = parameter.textureMinFilter;
            textureParameter.magFilter = parameter.textureMagFilter;
        }
        return getDependencyAssetDescriptors(tmxFile, textureParameter);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TiledMap loadTiledMap(FileHandle tmxFile, P parameter, ImageResolver imageResolver) {
        this.map = new TiledMap();
        if (parameter != null) {
            this.convertObjectToTileSpace = parameter.convertObjectToTileSpace;
            this.flipY = parameter.flipY;
        } else {
            this.convertObjectToTileSpace = false;
            this.flipY = true;
        }
        String mapOrientation = this.root.getAttribute("orientation", null);
        int mapWidth = this.root.getIntAttribute("width", 0);
        int mapHeight = this.root.getIntAttribute("height", 0);
        int tileWidth = this.root.getIntAttribute("tilewidth", 0);
        int tileHeight = this.root.getIntAttribute("tileheight", 0);
        int hexSideLength = this.root.getIntAttribute("hexsidelength", 0);
        String staggerAxis = this.root.getAttribute("staggeraxis", null);
        String staggerIndex = this.root.getAttribute("staggerindex", null);
        String mapBackgroundColor = this.root.getAttribute("backgroundcolor", null);
        MapProperties mapProperties = this.map.getProperties();
        if (mapOrientation != null) {
            mapProperties.put("orientation", mapOrientation);
        }
        mapProperties.put("width", Integer.valueOf(mapWidth));
        mapProperties.put("height", Integer.valueOf(mapHeight));
        mapProperties.put("tilewidth", Integer.valueOf(tileWidth));
        mapProperties.put("tileheight", Integer.valueOf(tileHeight));
        mapProperties.put("hexsidelength", Integer.valueOf(hexSideLength));
        if (staggerAxis != null) {
            mapProperties.put("staggeraxis", staggerAxis);
        }
        if (staggerIndex != null) {
            mapProperties.put("staggerindex", staggerIndex);
        }
        if (mapBackgroundColor != null) {
            mapProperties.put("backgroundcolor", mapBackgroundColor);
        }
        this.mapTileWidth = tileWidth;
        this.mapTileHeight = tileHeight;
        this.mapWidthInPixels = mapWidth * tileWidth;
        this.mapHeightInPixels = mapHeight * tileHeight;
        if (mapOrientation != null && "staggered".equals(mapOrientation) && mapHeight > 1) {
            this.mapWidthInPixels += tileWidth / 2;
            this.mapHeightInPixels = (this.mapHeightInPixels / 2) + (tileHeight / 2);
        }
        XmlReader.Element properties = this.root.getChildByName("properties");
        if (properties != null) {
            loadProperties(this.map.getProperties(), properties);
        }
        Array<XmlReader.Element> tilesets = this.root.getChildrenByName("tileset");
        for (Array.ArrayIterator<XmlReader.Element> it = tilesets.iterator(); it.hasNext(); it = it) {
            XmlReader.Element element = it.next();
            loadTileSet(element, tmxFile, imageResolver);
            this.root.removeChild(element);
        }
        int i = 0;
        int j = this.root.getChildCount();
        while (i < j) {
            String staggerAxis2 = staggerAxis;
            XmlReader.Element element2 = this.root.getChild(i);
            TiledMap tiledMap = this.map;
            loadLayer(tiledMap, tiledMap.getLayers(), element2, tmxFile, imageResolver);
            i++;
            staggerAxis = staggerAxis2;
            j = j;
            mapProperties = mapProperties;
            mapBackgroundColor = mapBackgroundColor;
        }
        return this.map;
    }

    protected void loadLayer(TiledMap map, MapLayers parentLayers, XmlReader.Element element, FileHandle tmxFile, ImageResolver imageResolver) {
        String name = element.getName();
        if (name.equals("group")) {
            loadLayerGroup(map, parentLayers, element, tmxFile, imageResolver);
        } else if (name.equals("layer")) {
            loadTileLayer(map, parentLayers, element);
        } else if (name.equals("objectgroup")) {
            loadObjectGroup(map, parentLayers, element);
        } else if (name.equals("imagelayer")) {
            loadImageLayer(map, parentLayers, element, tmxFile, imageResolver);
        }
    }

    protected void loadLayerGroup(TiledMap map, MapLayers parentLayers, XmlReader.Element element, FileHandle tmxFile, ImageResolver imageResolver) {
        if (element.getName().equals("group")) {
            MapGroupLayer groupLayer = new MapGroupLayer();
            loadBasicLayerInfo(groupLayer, element);
            XmlReader.Element properties = element.getChildByName("properties");
            if (properties != null) {
                loadProperties(groupLayer.getProperties(), properties);
            }
            int j = element.getChildCount();
            for (int i = 0; i < j; i++) {
                XmlReader.Element child = element.getChild(i);
                loadLayer(map, groupLayer.getLayers(), child, tmxFile, imageResolver);
            }
            Iterator<MapLayer> it = groupLayer.getLayers().iterator();
            while (it.hasNext()) {
                MapLayer layer = it.next();
                layer.setParent(groupLayer);
            }
            parentLayers.add(groupLayer);
        }
    }

    protected void loadTileLayer(TiledMap map, MapLayers parentLayers, XmlReader.Element element) {
        int width;
        if (element.getName().equals("layer")) {
            int width2 = element.getIntAttribute("width", 0);
            int height = element.getIntAttribute("height", 0);
            int tileWidth = ((Integer) map.getProperties().get("tilewidth", Integer.class)).intValue();
            int tileHeight = ((Integer) map.getProperties().get("tileheight", Integer.class)).intValue();
            TiledMapTileLayer layer = new TiledMapTileLayer(width2, height, tileWidth, tileHeight);
            loadBasicLayerInfo(layer, element);
            int[] ids = getTileIds(element, width2, height);
            TiledMapTileSets tilesets = map.getTileSets();
            for (int y = 0; y < height; y++) {
                int x = 0;
                while (x < width2) {
                    int id = ids[(y * width2) + x];
                    boolean flipHorizontally = (Integer.MIN_VALUE & id) != 0;
                    boolean flipVertically = (FLAG_FLIP_VERTICALLY & id) != 0;
                    boolean flipDiagonally = (id & FLAG_FLIP_DIAGONALLY) != 0;
                    TiledMapTile tile = tilesets.getTile(id & 536870911);
                    if (tile != null) {
                        width = width2;
                        TiledMapTileLayer.Cell cell = createTileLayerCell(flipHorizontally, flipVertically, flipDiagonally);
                        cell.setTile(tile);
                        layer.setCell(x, this.flipY ? (height - 1) - y : y, cell);
                    } else {
                        width = width2;
                    }
                    x++;
                    width2 = width;
                }
            }
            XmlReader.Element properties = element.getChildByName("properties");
            if (properties != null) {
                loadProperties(layer.getProperties(), properties);
            }
            parentLayers.add(layer);
        }
    }

    protected void loadObjectGroup(TiledMap map, MapLayers parentLayers, XmlReader.Element element) {
        if (element.getName().equals("objectgroup")) {
            MapLayer layer = new MapLayer();
            loadBasicLayerInfo(layer, element);
            XmlReader.Element properties = element.getChildByName("properties");
            if (properties != null) {
                loadProperties(layer.getProperties(), properties);
            }
            Array.ArrayIterator<XmlReader.Element> it = element.getChildrenByName("object").iterator();
            while (it.hasNext()) {
                XmlReader.Element objectElement = it.next();
                loadObject(map, layer, objectElement);
            }
            parentLayers.add(layer);
        }
    }

    protected void loadImageLayer(TiledMap map, MapLayers parentLayers, XmlReader.Element element, FileHandle tmxFile, ImageResolver imageResolver) {
        float x;
        float y;
        if (element.getName().equals("imagelayer")) {
            if (element.hasAttribute("offsetx")) {
                x = Float.parseFloat(element.getAttribute("offsetx", "0"));
            } else {
                x = Float.parseFloat(element.getAttribute("x", "0"));
            }
            if (element.hasAttribute("offsety")) {
                y = Float.parseFloat(element.getAttribute("offsety", "0"));
            } else {
                y = Float.parseFloat(element.getAttribute("y", "0"));
            }
            if (this.flipY) {
                y = this.mapHeightInPixels - y;
            }
            TextureRegion texture = null;
            XmlReader.Element image = element.getChildByName("image");
            if (image != null) {
                String source = image.getAttribute("source");
                FileHandle handle = getRelativeFileHandle(tmxFile, source);
                texture = imageResolver.getImage(handle.path());
                y -= texture.getRegionHeight();
            }
            TiledMapImageLayer layer = new TiledMapImageLayer(texture, x, y);
            loadBasicLayerInfo(layer, element);
            XmlReader.Element properties = element.getChildByName("properties");
            if (properties != null) {
                loadProperties(layer.getProperties(), properties);
            }
            parentLayers.add(layer);
        }
    }

    protected void loadBasicLayerInfo(MapLayer layer, XmlReader.Element element) {
        String name = element.getAttribute("name", null);
        float opacity = Float.parseFloat(element.getAttribute("opacity", BuildConfig.VERSION_NAME));
        boolean visible = element.getIntAttribute("visible", 1) == 1;
        float offsetX = element.getFloatAttribute("offsetx", 0.0f);
        float offsetY = element.getFloatAttribute("offsety", 0.0f);
        layer.setName(name);
        layer.setOpacity(opacity);
        layer.setVisible(visible);
        layer.setOffsetX(offsetX);
        layer.setOffsetY(offsetY);
    }

    protected void loadObject(TiledMap map, MapLayer layer, XmlReader.Element element) {
        loadObject(map, layer.getObjects(), element, this.mapHeightInPixels);
    }

    protected void loadObject(TiledMap map, TiledMapTile tile, XmlReader.Element element) {
        loadObject(map, tile.getObjects(), element, tile.getTextureRegion().getRegionHeight());
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0206  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x021d  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0255  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0268  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0276  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x02b7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected void loadObject(com.badlogic.gdx.maps.tiled.TiledMap r29, com.badlogic.gdx.maps.MapObjects r30, com.badlogic.gdx.utils.XmlReader.Element r31, float r32) {
        /*
            Method dump skipped, instructions count: 711
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.badlogic.gdx.maps.tiled.BaseTmxMapLoader.loadObject(com.badlogic.gdx.maps.tiled.TiledMap, com.badlogic.gdx.maps.MapObjects, com.badlogic.gdx.utils.XmlReader$Element, float):void");
    }

    protected void loadProperties(MapProperties properties, XmlReader.Element element) {
        if (element != null && element.getName().equals("properties")) {
            Array.ArrayIterator<XmlReader.Element> it = element.getChildrenByName("property").iterator();
            while (it.hasNext()) {
                XmlReader.Element property = it.next();
                String name = property.getAttribute("name", null);
                String value = property.getAttribute("value", null);
                String type = property.getAttribute("type", null);
                if (value == null) {
                    value = property.getText();
                }
                Object castValue = castProperty(name, value, type);
                properties.put(name, castValue);
            }
        }
    }

    protected Object castProperty(String name, String value, String type) {
        if (type == null) {
            return value;
        }
        if (type.equals("int")) {
            return Integer.valueOf(value);
        }
        if (type.equals("float")) {
            return Float.valueOf(value);
        }
        if (type.equals("bool")) {
            return Boolean.valueOf(value);
        }
        if (type.equals("color")) {
            String opaqueColor = value.substring(3);
            String alpha = value.substring(1, 3);
            return Color.valueOf(opaqueColor + alpha);
        }
        throw new GdxRuntimeException("Wrong type given for property " + name + ", given : " + type + ", supported : string, bool, int, float, color");
    }

    protected TiledMapTileLayer.Cell createTileLayerCell(boolean flipHorizontally, boolean flipVertically, boolean flipDiagonally) {
        TiledMapTileLayer.Cell cell = new TiledMapTileLayer.Cell();
        if (!flipDiagonally) {
            cell.setFlipHorizontally(flipHorizontally);
            cell.setFlipVertically(flipVertically);
        } else if (flipHorizontally && flipVertically) {
            cell.setFlipHorizontally(true);
            cell.setRotation(3);
        } else if (flipHorizontally) {
            cell.setRotation(3);
        } else if (flipVertically) {
            cell.setRotation(1);
        } else {
            cell.setFlipVertically(true);
            cell.setRotation(3);
        }
        return cell;
    }

    public static int[] getTileIds(XmlReader.Element element, int width, int height) {
        InputStream is;
        int curr;
        XmlReader.Element data = element.getChildByName("data");
        String encoding = data.getAttribute("encoding", null);
        if (encoding == null) {
            throw new GdxRuntimeException("Unsupported encoding (XML) for TMX Layer Data");
        }
        int[] ids = new int[width * height];
        if (encoding.equals("csv")) {
            String[] array = data.getText().split(",");
            for (int i = 0; i < array.length; i++) {
                ids[i] = (int) Long.parseLong(array[i].trim());
            }
        } else if (encoding.equals("base64")) {
            InputStream is2 = null;
            try {
                try {
                    String compression = data.getAttribute("compression", null);
                    byte[] bytes = Base64Coder.decode(data.getText());
                    if (compression == null) {
                        is = new ByteArrayInputStream(bytes);
                    } else if (compression.equals("gzip")) {
                        is = new BufferedInputStream(new GZIPInputStream(new ByteArrayInputStream(bytes), bytes.length));
                    } else if (compression.equals("zlib")) {
                        is = new BufferedInputStream(new InflaterInputStream(new ByteArrayInputStream(bytes)));
                    } else {
                        throw new GdxRuntimeException("Unrecognised compression (" + compression + ") for TMX Layer Data");
                    }
                    byte[] temp = new byte[4];
                    for (int y = 0; y < height; y++) {
                        for (int x = 0; x < width; x++) {
                            int read = is2.read(temp);
                            while (read < temp.length && (curr = is2.read(temp, read, temp.length - read)) != -1) {
                                read += curr;
                            }
                            if (read != temp.length) {
                                throw new GdxRuntimeException("Error Reading TMX Layer Data: Premature end of tile data");
                            }
                            ids[(y * width) + x] = unsignedByteToInt(temp[0]) | (unsignedByteToInt(temp[1]) << 8) | (unsignedByteToInt(temp[2]) << 16) | (unsignedByteToInt(temp[3]) << 24);
                        }
                    }
                } catch (IOException e) {
                    throw new GdxRuntimeException("Error Reading TMX Layer Data - IOException: " + e.getMessage());
                }
            } finally {
                StreamUtils.closeQuietly(is2);
            }
        } else {
            throw new GdxRuntimeException("Unrecognised encoding (" + encoding + ") for TMX Layer Data");
        }
        return ids;
    }

    protected static int unsignedByteToInt(byte b) {
        return b & UByte.MAX_VALUE;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static FileHandle getRelativeFileHandle(FileHandle file, String path) {
        StringTokenizer tokenizer = new StringTokenizer(path, "\\/");
        FileHandle result = file.parent();
        while (tokenizer.hasMoreElements()) {
            String token = tokenizer.nextToken();
            if (token.equals("..")) {
                result = result.parent();
            } else {
                result = result.child(token);
            }
        }
        return result;
    }

    protected void loadTileSet(XmlReader.Element element, FileHandle tmxFile, ImageResolver imageResolver) {
        int i;
        XmlReader.Element imageElement;
        String imageSource;
        int imageWidth;
        int imageHeight;
        FileHandle image;
        int offsetX;
        int offsetY;
        if (element.getName().equals("tileset")) {
            int firstgid = element.getIntAttribute("firstgid", 1);
            String imageSource2 = BuildConfig.FLAVOR;
            int imageWidth2 = 0;
            int imageHeight2 = 0;
            FileHandle image2 = null;
            String source = element.getAttribute("source", null);
            if (source != null) {
                FileHandle tsx = getRelativeFileHandle(tmxFile, source);
                try {
                    XmlReader.Element element2 = this.xml.parse(tsx);
                    try {
                        XmlReader.Element imageElement2 = element2.getChildByName("image");
                        if (imageElement2 != null) {
                            imageSource2 = imageElement2.getAttribute("source");
                            imageWidth2 = imageElement2.getIntAttribute("width", 0);
                            imageHeight2 = imageElement2.getIntAttribute("height", 0);
                            image2 = getRelativeFileHandle(tsx, imageSource2);
                        }
                        imageElement = element2;
                        imageSource = imageSource2;
                        imageWidth = imageWidth2;
                        imageHeight = imageHeight2;
                        image = image2;
                        i = 0;
                    } catch (SerializationException e) {
                        throw new GdxRuntimeException("Error parsing external tileset.");
                    }
                } catch (SerializationException e2) {
                }
            } else {
                XmlReader.Element imageElement3 = element.getChildByName("image");
                if (imageElement3 == null) {
                    i = 0;
                    imageElement = element;
                    imageSource = BuildConfig.FLAVOR;
                    imageWidth = 0;
                    imageHeight = 0;
                    image = null;
                } else {
                    String imageSource3 = imageElement3.getAttribute("source");
                    i = 0;
                    int imageWidth3 = imageElement3.getIntAttribute("width", 0);
                    int imageHeight3 = imageElement3.getIntAttribute("height", 0);
                    FileHandle image3 = getRelativeFileHandle(tmxFile, imageSource3);
                    imageElement = element;
                    imageSource = imageSource3;
                    imageWidth = imageWidth3;
                    imageHeight = imageHeight3;
                    image = image3;
                }
            }
            String name = imageElement.get("name", null);
            int tilewidth = imageElement.getIntAttribute("tilewidth", i);
            int tileheight = imageElement.getIntAttribute("tileheight", i);
            int spacing = imageElement.getIntAttribute("spacing", i);
            int margin = imageElement.getIntAttribute("margin", i);
            XmlReader.Element offset = imageElement.getChildByName("tileoffset");
            if (offset == null) {
                offsetX = 0;
                offsetY = 0;
            } else {
                int offsetX2 = offset.getIntAttribute("x", 0);
                int offsetY2 = offset.getIntAttribute("y", 0);
                offsetX = offsetX2;
                offsetY = offsetY2;
            }
            TiledMapTileSet tileSet = new TiledMapTileSet();
            tileSet.setName(name);
            MapProperties tileSetProperties = tileSet.getProperties();
            XmlReader.Element properties = imageElement.getChildByName("properties");
            if (properties != null) {
                loadProperties(tileSetProperties, properties);
            }
            tileSetProperties.put("firstgid", Integer.valueOf(firstgid));
            Array<XmlReader.Element> tileElements = imageElement.getChildrenByName("tile");
            TiledMapTileSet tileSet2 = tileSet;
            int firstgid2 = firstgid;
            addStaticTiles(tmxFile, imageResolver, tileSet, imageElement, tileElements, name, firstgid, tilewidth, tileheight, spacing, margin, source, offsetX, offsetY, imageSource, imageWidth, imageHeight, image);
            Array<AnimatedTiledMapTile> animatedTiles = new Array<>();
            Array.ArrayIterator<XmlReader.Element> it = tileElements.iterator();
            while (it.hasNext()) {
                XmlReader.Element tileElement = it.next();
                int localtid = tileElement.getIntAttribute("id", 0);
                int firstgid3 = firstgid2;
                TiledMapTileSet tileSet3 = tileSet2;
                TiledMapTile tile = tileSet3.getTile(firstgid3 + localtid);
                if (tile != null) {
                    AnimatedTiledMapTile animatedTile = createAnimatedTile(tileSet3, tile, tileElement, firstgid3);
                    if (animatedTile != null) {
                        animatedTiles.add(animatedTile);
                        tile = animatedTile;
                    }
                    addTileProperties(tile, tileElement);
                    addTileObjectGroup(tile, tileElement);
                }
                firstgid2 = firstgid3;
                tileSet2 = tileSet3;
            }
            TiledMapTileSet tileSet4 = tileSet2;
            Array.ArrayIterator<AnimatedTiledMapTile> it2 = animatedTiles.iterator();
            while (it2.hasNext()) {
                AnimatedTiledMapTile animatedTile2 = (AnimatedTiledMapTile) it2.next();
                tileSet4.putTile(animatedTile2.getId(), animatedTile2);
            }
            this.map.getTileSets().addTileSet(tileSet4);
        }
    }

    protected void addTileProperties(TiledMapTile tile, XmlReader.Element tileElement) {
        String terrain = tileElement.getAttribute("terrain", null);
        if (terrain != null) {
            tile.getProperties().put("terrain", terrain);
        }
        String probability = tileElement.getAttribute("probability", null);
        if (probability != null) {
            tile.getProperties().put("probability", probability);
        }
        XmlReader.Element properties = tileElement.getChildByName("properties");
        if (properties != null) {
            loadProperties(tile.getProperties(), properties);
        }
    }

    protected void addTileObjectGroup(TiledMapTile tile, XmlReader.Element tileElement) {
        XmlReader.Element objectgroupElement = tileElement.getChildByName("objectgroup");
        if (objectgroupElement != null) {
            Array.ArrayIterator<XmlReader.Element> it = objectgroupElement.getChildrenByName("object").iterator();
            while (it.hasNext()) {
                XmlReader.Element objectElement = it.next();
                loadObject(this.map, tile, objectElement);
            }
        }
    }

    protected AnimatedTiledMapTile createAnimatedTile(TiledMapTileSet tileSet, TiledMapTile tile, XmlReader.Element tileElement, int firstgid) {
        XmlReader.Element animationElement = tileElement.getChildByName("animation");
        if (animationElement != null) {
            Array<StaticTiledMapTile> staticTiles = new Array<>();
            IntArray intervals = new IntArray();
            Array.ArrayIterator<XmlReader.Element> it = animationElement.getChildrenByName("frame").iterator();
            while (it.hasNext()) {
                XmlReader.Element frameElement = it.next();
                staticTiles.add((StaticTiledMapTile) tileSet.getTile(frameElement.getIntAttribute("tileid") + firstgid));
                intervals.add(frameElement.getIntAttribute("duration"));
            }
            AnimatedTiledMapTile animatedTile = new AnimatedTiledMapTile(intervals, staticTiles);
            animatedTile.setId(tile.getId());
            return animatedTile;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void addStaticTiledMapTile(TiledMapTileSet tileSet, TextureRegion textureRegion, int tileId, float offsetX, float offsetY) {
        TiledMapTile tile = new StaticTiledMapTile(textureRegion);
        tile.setId(tileId);
        tile.setOffsetX(offsetX);
        tile.setOffsetY(this.flipY ? -offsetY : offsetY);
        tileSet.putTile(tileId, tile);
    }
}