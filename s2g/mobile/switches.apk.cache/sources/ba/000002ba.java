package com.badlogic.gdx.maps.tiled;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.SynchronousAssetLoader;
import com.badlogic.gdx.assets.loaders.resolvers.InternalFileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.ImageResolver;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.TiledMapTileLayer;
import com.badlogic.gdx.maps.tiled.tiles.AnimatedTiledMapTile;
import com.badlogic.gdx.maps.tiled.tiles.StaticTiledMapTile;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.XmlReader;
import java.io.IOException;
import java.util.Iterator;
import java.util.StringTokenizer;

/* loaded from: classes.dex */
public class TideMapLoader extends SynchronousAssetLoader<TiledMap, Parameters> {
    private XmlReader.Element root;
    private XmlReader xml;

    /* loaded from: classes.dex */
    public static class Parameters extends AssetLoaderParameters<TiledMap> {
    }

    public TideMapLoader() {
        super(new InternalFileHandleResolver());
        this.xml = new XmlReader();
    }

    public TideMapLoader(FileHandleResolver resolver) {
        super(resolver);
        this.xml = new XmlReader();
    }

    public TiledMap load(String fileName) {
        try {
            FileHandle tideFile = resolve(fileName);
            this.root = this.xml.parse(tideFile);
            ObjectMap<String, Texture> textures = new ObjectMap<>();
            Array.ArrayIterator<FileHandle> it = loadTileSheets(this.root, tideFile).iterator();
            while (it.hasNext()) {
                FileHandle textureFile = it.next();
                textures.put(textureFile.path(), new Texture(textureFile));
            }
            ImageResolver.DirectImageResolver imageResolver = new ImageResolver.DirectImageResolver(textures);
            TiledMap map = loadMap(this.root, tideFile, imageResolver);
            map.setOwnedResources(textures.values().toArray());
            return map;
        } catch (IOException e) {
            throw new GdxRuntimeException("Couldn't load tilemap '" + fileName + "'", e);
        }
    }

    @Override // com.badlogic.gdx.assets.loaders.SynchronousAssetLoader
    public TiledMap load(AssetManager assetManager, String fileName, FileHandle tideFile, Parameters parameter) {
        try {
            return loadMap(this.root, tideFile, new ImageResolver.AssetManagerImageResolver(assetManager));
        } catch (Exception e) {
            throw new GdxRuntimeException("Couldn't load tilemap '" + fileName + "'", e);
        }
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle tmxFile, Parameters parameter) {
        Array<AssetDescriptor> dependencies = new Array<>();
        try {
            this.root = this.xml.parse(tmxFile);
            Array.ArrayIterator<FileHandle> it = loadTileSheets(this.root, tmxFile).iterator();
            while (it.hasNext()) {
                FileHandle image = it.next();
                dependencies.add(new AssetDescriptor(image.path(), Texture.class));
            }
            return dependencies;
        } catch (IOException e) {
            throw new GdxRuntimeException("Couldn't load tilemap '" + fileName + "'", e);
        }
    }

    private TiledMap loadMap(XmlReader.Element root, FileHandle tmxFile, ImageResolver imageResolver) {
        TiledMap map = new TiledMap();
        XmlReader.Element properties = root.getChildByName("Properties");
        if (properties != null) {
            loadProperties(map.getProperties(), properties);
        }
        XmlReader.Element tilesheets = root.getChildByName("TileSheets");
        Array.ArrayIterator<XmlReader.Element> it = tilesheets.getChildrenByName("TileSheet").iterator();
        while (it.hasNext()) {
            XmlReader.Element tilesheet = it.next();
            loadTileSheet(map, tilesheet, tmxFile, imageResolver);
        }
        XmlReader.Element layers = root.getChildByName("Layers");
        Array.ArrayIterator<XmlReader.Element> it2 = layers.getChildrenByName("Layer").iterator();
        while (it2.hasNext()) {
            XmlReader.Element layer = it2.next();
            loadLayer(map, layer);
        }
        return map;
    }

    private Array<FileHandle> loadTileSheets(XmlReader.Element root, FileHandle tideFile) throws IOException {
        Array<FileHandle> images = new Array<>();
        XmlReader.Element tilesheets = root.getChildByName("TileSheets");
        Array.ArrayIterator<XmlReader.Element> it = tilesheets.getChildrenByName("TileSheet").iterator();
        while (it.hasNext()) {
            XmlReader.Element tileset = it.next();
            XmlReader.Element imageSource = tileset.getChildByName("ImageSource");
            FileHandle image = getRelativeFileHandle(tideFile, imageSource.getText());
            images.add(image);
        }
        return images;
    }

    private void loadTileSheet(TiledMap map, XmlReader.Element element, FileHandle tideFile, ImageResolver imageResolver) {
        if (element.getName().equals("TileSheet")) {
            String id = element.getAttribute("Id");
            element.getChildByName("Description").getText();
            String imageSource = element.getChildByName("ImageSource").getText();
            XmlReader.Element alignment = element.getChildByName("Alignment");
            String sheetSize = alignment.getAttribute("SheetSize");
            String tileSize = alignment.getAttribute("TileSize");
            String margin = alignment.getAttribute("Margin");
            String spacing = alignment.getAttribute("Spacing");
            String[] sheetSizeParts = sheetSize.split(" x ");
            Integer.parseInt(sheetSizeParts[0]);
            Integer.parseInt(sheetSizeParts[1]);
            String[] tileSizeParts = tileSize.split(" x ");
            int tileSizeX = Integer.parseInt(tileSizeParts[0]);
            int tileSizeY = Integer.parseInt(tileSizeParts[1]);
            String[] marginParts = margin.split(" x ");
            int marginX = Integer.parseInt(marginParts[0]);
            int marginY = Integer.parseInt(marginParts[1]);
            String[] spacingParts = margin.split(" x ");
            int spacingX = Integer.parseInt(spacingParts[0]);
            int spacingY = Integer.parseInt(spacingParts[1]);
            FileHandle image = getRelativeFileHandle(tideFile, imageSource);
            TextureRegion texture = imageResolver.getImage(image.path());
            TiledMapTileSets tilesets = map.getTileSets();
            Iterator<TiledMapTileSet> it = tilesets.iterator();
            int firstgid = 1;
            while (it.hasNext()) {
                firstgid += it.next().size();
            }
            TiledMapTileSet tileset = new TiledMapTileSet();
            tileset.setName(id);
            tileset.getProperties().put("firstgid", Integer.valueOf(firstgid));
            int gid = firstgid;
            int stopWidth = texture.getRegionWidth() - tileSizeX;
            int stopHeight = texture.getRegionHeight() - tileSizeY;
            int gid2 = gid;
            int gid3 = marginY;
            while (gid3 <= stopHeight) {
                int stopHeight2 = stopHeight;
                String margin2 = margin;
                int gid4 = gid2;
                int stopHeight3 = marginX;
                while (stopHeight3 <= stopWidth) {
                    int stopWidth2 = stopWidth;
                    TiledMapTile tile = new StaticTiledMapTile(new TextureRegion(texture, stopHeight3, gid3, tileSizeX, tileSizeY));
                    tile.setId(gid4);
                    tileset.putTile(gid4, tile);
                    stopHeight3 += tileSizeX + spacingX;
                    gid4++;
                    stopWidth = stopWidth2;
                    spacing = spacing;
                }
                int stopWidth3 = stopWidth;
                int stopWidth4 = tileSizeY + spacingY;
                gid3 += stopWidth4;
                gid2 = gid4;
                stopHeight = stopHeight2;
                margin = margin2;
                stopWidth = stopWidth3;
            }
            XmlReader.Element properties = element.getChildByName("Properties");
            if (properties != null) {
                loadProperties(tileset.getProperties(), properties);
            }
            tilesets.addTileSet(tileset);
        }
    }

    private void loadLayer(TiledMap map, XmlReader.Element element) {
        int layerSizeY;
        XmlReader.Element tileArray;
        Array<XmlReader.Element> rows;
        String str;
        TiledMapTileSet currentTileSet;
        Array<StaticTiledMapTile> frameTiles;
        if (element.getName().equals("Layer")) {
            String id = element.getAttribute("Id");
            String visible = element.getAttribute("Visible");
            XmlReader.Element dimensions = element.getChildByName("Dimensions");
            String layerSize = dimensions.getAttribute("LayerSize");
            String tileSize = dimensions.getAttribute("TileSize");
            String[] layerSizeParts = layerSize.split(" x ");
            int layerSizeX = Integer.parseInt(layerSizeParts[0]);
            int layerSizeY2 = Integer.parseInt(layerSizeParts[1]);
            String[] tileSizeParts = tileSize.split(" x ");
            int tileSizeX = Integer.parseInt(tileSizeParts[0]);
            int tileSizeY = Integer.parseInt(tileSizeParts[1]);
            TiledMapTileLayer layer = new TiledMapTileLayer(layerSizeX, layerSizeY2, tileSizeX, tileSizeY);
            layer.setName(id);
            layer.setVisible(visible.equalsIgnoreCase("True"));
            XmlReader.Element tileArray2 = element.getChildByName("TileArray");
            Array<XmlReader.Element> rows2 = tileArray2.getChildrenByName("Row");
            TiledMapTileSets tilesets = map.getTileSets();
            TiledMapTileSet currentTileSet2 = null;
            int firstgid = 0;
            int y = rows2.size;
            int row = 0;
            while (row < y) {
                XmlReader.Element dimensions2 = dimensions;
                XmlReader.Element currentRow = rows2.get(row);
                int rowCount = y;
                int rowCount2 = (y - 1) - row;
                String layerSize2 = layerSize;
                int childCount = currentRow.getChildCount();
                String tileSize2 = tileSize;
                int child = 0;
                String[] layerSizeParts2 = layerSizeParts;
                TiledMapTileSet currentTileSet3 = currentTileSet2;
                String[] tileSizeParts2 = tileSizeParts;
                int x = 0;
                while (child < childCount) {
                    int childCount2 = childCount;
                    XmlReader.Element currentChild = currentRow.getChild(child);
                    XmlReader.Element currentRow2 = currentRow;
                    String name = currentChild.getName();
                    int tileSizeX2 = tileSizeX;
                    String str2 = "TileSheet";
                    int layerSizeX2 = layerSizeX;
                    int tileSizeY2 = tileSizeY;
                    if (name.equals("TileSheet")) {
                        currentTileSet3 = tilesets.getTileSet(currentChild.getAttribute("Ref"));
                        firstgid = ((Integer) currentTileSet3.getProperties().get("firstgid", Integer.class)).intValue();
                        layerSizeY = layerSizeY2;
                        tileArray = tileArray2;
                        rows = rows2;
                    } else {
                        layerSizeY = layerSizeY2;
                        if (name.equals("Null")) {
                            x += currentChild.getIntAttribute("Count");
                            tileArray = tileArray2;
                            rows = rows2;
                        } else {
                            tileArray = tileArray2;
                            if (name.equals("Static")) {
                                TiledMapTileLayer.Cell cell = new TiledMapTileLayer.Cell();
                                cell.setTile(currentTileSet3.getTile(firstgid + currentChild.getIntAttribute("Index")));
                                layer.setCell(x, rowCount2, cell);
                                x++;
                                rows = rows2;
                            } else {
                                TiledMapTileSet currentTileSet4 = currentTileSet3;
                                if (name.equals("Animated")) {
                                    int interval = currentChild.getInt("Interval");
                                    XmlReader.Element frames = currentChild.getChildByName("Frames");
                                    Array<StaticTiledMapTile> frameTiles2 = new Array<>();
                                    int frameChildCount = frames.getChildCount();
                                    rows = rows2;
                                    TiledMapTileSet currentTileSet5 = currentTileSet4;
                                    int frameChild = 0;
                                    while (frameChild < frameChildCount) {
                                        int frameChildCount2 = frameChildCount;
                                        XmlReader.Element frame = frames.getChild(frameChild);
                                        XmlReader.Element frames2 = frames;
                                        String frameName = frame.getName();
                                        if (frameName.equals(str2)) {
                                            str = str2;
                                            TiledMapTileSet currentTileSet6 = tilesets.getTileSet(frame.getAttribute("Ref"));
                                            currentTileSet = currentTileSet6;
                                            firstgid = ((Integer) currentTileSet6.getProperties().get("firstgid", Integer.class)).intValue();
                                            frameTiles = frameTiles2;
                                        } else {
                                            str = str2;
                                            if (!frameName.equals("Static")) {
                                                currentTileSet = currentTileSet5;
                                                frameTiles = frameTiles2;
                                            } else {
                                                currentTileSet = currentTileSet5;
                                                frameTiles = frameTiles2;
                                                frameTiles.add((StaticTiledMapTile) currentTileSet5.getTile(firstgid + frame.getIntAttribute("Index")));
                                            }
                                        }
                                        frameChild++;
                                        frameTiles2 = frameTiles;
                                        currentTileSet5 = currentTileSet;
                                        frameChildCount = frameChildCount2;
                                        frames = frames2;
                                        str2 = str;
                                    }
                                    TiledMapTileLayer.Cell cell2 = new TiledMapTileLayer.Cell();
                                    cell2.setTile(new AnimatedTiledMapTile(interval / 1000.0f, frameTiles2));
                                    layer.setCell(x, rowCount2, cell2);
                                    x++;
                                    currentTileSet3 = currentTileSet5;
                                } else {
                                    rows = rows2;
                                    currentTileSet3 = currentTileSet4;
                                }
                            }
                        }
                    }
                    child++;
                    childCount = childCount2;
                    currentRow = currentRow2;
                    tileSizeX = tileSizeX2;
                    layerSizeX = layerSizeX2;
                    tileSizeY = tileSizeY2;
                    layerSizeY2 = layerSizeY;
                    tileArray2 = tileArray;
                    rows2 = rows;
                }
                currentTileSet2 = currentTileSet3;
                row++;
                tileSizeParts = tileSizeParts2;
                dimensions = dimensions2;
                y = rowCount;
                layerSizeParts = layerSizeParts2;
                layerSize = layerSize2;
                tileSize = tileSize2;
            }
            XmlReader.Element properties = element.getChildByName("Properties");
            if (properties != null) {
                loadProperties(layer.getProperties(), properties);
            }
            map.getLayers().add(layer);
        }
    }

    private void loadProperties(MapProperties properties, XmlReader.Element element) {
        if (element.getName().equals("Properties")) {
            Array.ArrayIterator<XmlReader.Element> it = element.getChildrenByName("Property").iterator();
            while (it.hasNext()) {
                XmlReader.Element property = it.next();
                String key = property.getAttribute("Key", null);
                String type = property.getAttribute("Type", null);
                String value = property.getText();
                if (type.equals("Int32")) {
                    properties.put(key, Integer.valueOf(Integer.parseInt(value)));
                } else if (type.equals("String")) {
                    properties.put(key, value);
                } else if (type.equals("Boolean")) {
                    properties.put(key, Boolean.valueOf(value.equalsIgnoreCase("true")));
                } else {
                    properties.put(key, value);
                }
            }
        }
    }

    private static FileHandle getRelativeFileHandle(FileHandle file, String path) {
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
}