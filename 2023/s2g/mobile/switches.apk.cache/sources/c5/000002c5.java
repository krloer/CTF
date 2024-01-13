package com.badlogic.gdx.maps.tiled;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.assets.loaders.resolvers.InternalFileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.ImageResolver;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.BaseTmxMapLoader;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.ObjectMap;
import com.badlogic.gdx.utils.XmlReader;

/* loaded from: classes.dex */
public class TmxMapLoader extends BaseTmxMapLoader<Parameters> {

    /* loaded from: classes.dex */
    public static class Parameters extends BaseTmxMapLoader.Parameters {
    }

    public TmxMapLoader() {
        super(new InternalFileHandleResolver());
    }

    public TmxMapLoader(FileHandleResolver resolver) {
        super(resolver);
    }

    public TiledMap load(String fileName) {
        return load(fileName, new Parameters());
    }

    public TiledMap load(String fileName, Parameters parameter) {
        FileHandle tmxFile = resolve(fileName);
        this.root = this.xml.parse(tmxFile);
        ObjectMap<String, Texture> textures = new ObjectMap<>();
        Array<FileHandle> textureFiles = getDependencyFileHandles(tmxFile);
        Array.ArrayIterator<FileHandle> it = textureFiles.iterator();
        while (it.hasNext()) {
            FileHandle textureFile = it.next();
            Texture texture = new Texture(textureFile, parameter.generateMipMaps);
            texture.setFilter(parameter.textureMinFilter, parameter.textureMagFilter);
            textures.put(textureFile.path(), texture);
        }
        TiledMap map = loadTiledMap(tmxFile, parameter, new ImageResolver.DirectImageResolver(textures));
        map.setOwnedResources(textures.values().toArray());
        return map;
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle tmxFile, Parameters parameter) {
        this.map = loadTiledMap(tmxFile, parameter, new ImageResolver.AssetManagerImageResolver(manager));
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public TiledMap loadSync(AssetManager manager, String fileName, FileHandle file, Parameters parameter) {
        return this.map;
    }

    @Override // com.badlogic.gdx.maps.tiled.BaseTmxMapLoader
    protected Array<AssetDescriptor> getDependencyAssetDescriptors(FileHandle tmxFile, TextureLoader.TextureParameter textureParameter) {
        Array<AssetDescriptor> descriptors = new Array<>();
        Array<FileHandle> fileHandles = getDependencyFileHandles(tmxFile);
        Array.ArrayIterator<FileHandle> it = fileHandles.iterator();
        while (it.hasNext()) {
            FileHandle handle = it.next();
            descriptors.add(new AssetDescriptor(handle, Texture.class, textureParameter));
        }
        return descriptors;
    }

    protected Array<FileHandle> getDependencyFileHandles(FileHandle tmxFile) {
        Array<FileHandle> fileHandles = new Array<>();
        Array.ArrayIterator<XmlReader.Element> it = this.root.getChildrenByName("tileset").iterator();
        while (it.hasNext()) {
            XmlReader.Element tileset = it.next();
            String source = tileset.getAttribute("source", null);
            if (source != null) {
                FileHandle tsxFile = getRelativeFileHandle(tmxFile, source);
                XmlReader.Element tileset2 = this.xml.parse(tsxFile);
                XmlReader.Element imageElement = tileset2.getChildByName("image");
                if (imageElement != null) {
                    String imageSource = tileset2.getChildByName("image").getAttribute("source");
                    FileHandle image = getRelativeFileHandle(tsxFile, imageSource);
                    fileHandles.add(image);
                } else {
                    Array.ArrayIterator<XmlReader.Element> it2 = tileset2.getChildrenByName("tile").iterator();
                    while (it2.hasNext()) {
                        XmlReader.Element tile = it2.next();
                        String imageSource2 = tile.getChildByName("image").getAttribute("source");
                        FileHandle image2 = getRelativeFileHandle(tsxFile, imageSource2);
                        fileHandles.add(image2);
                    }
                }
            } else {
                XmlReader.Element imageElement2 = tileset.getChildByName("image");
                if (imageElement2 != null) {
                    String imageSource3 = tileset.getChildByName("image").getAttribute("source");
                    FileHandle image3 = getRelativeFileHandle(tmxFile, imageSource3);
                    fileHandles.add(image3);
                } else {
                    Array.ArrayIterator<XmlReader.Element> it3 = tileset.getChildrenByName("tile").iterator();
                    while (it3.hasNext()) {
                        XmlReader.Element tile2 = it3.next();
                        String imageSource4 = tile2.getChildByName("image").getAttribute("source");
                        FileHandle image4 = getRelativeFileHandle(tmxFile, imageSource4);
                        fileHandles.add(image4);
                    }
                }
            }
        }
        Array.ArrayIterator<XmlReader.Element> it4 = this.root.getChildrenByName("imagelayer").iterator();
        while (it4.hasNext()) {
            XmlReader.Element imageLayer = it4.next();
            XmlReader.Element image5 = imageLayer.getChildByName("image");
            String source2 = image5.getAttribute("source", null);
            if (source2 != null) {
                FileHandle handle = getRelativeFileHandle(tmxFile, source2);
                fileHandles.add(handle);
            }
        }
        return fileHandles;
    }

    @Override // com.badlogic.gdx.maps.tiled.BaseTmxMapLoader
    protected void addStaticTiles(FileHandle tmxFile, ImageResolver imageResolver, TiledMapTileSet tileSet, XmlReader.Element element, Array<XmlReader.Element> tileElements, String name, int firstgid, int tilewidth, int tileheight, int spacing, int margin, String source, int offsetX, int offsetY, String imageSource, int imageWidth, int imageHeight, FileHandle image) {
        MapProperties props = tileSet.getProperties();
        if (image != null) {
            TextureRegion texture = imageResolver.getImage(image.path());
            props.put("imagesource", imageSource);
            props.put("imagewidth", Integer.valueOf(imageWidth));
            props.put("imageheight", Integer.valueOf(imageHeight));
            props.put("tilewidth", Integer.valueOf(tilewidth));
            props.put("tileheight", Integer.valueOf(tileheight));
            props.put("margin", Integer.valueOf(margin));
            props.put("spacing", Integer.valueOf(spacing));
            int stopWidth = texture.getRegionWidth() - tilewidth;
            int stopHeight = texture.getRegionHeight() - tileheight;
            int id = firstgid;
            int y = margin;
            while (y <= stopHeight) {
                int id2 = id;
                int x = margin;
                while (x <= stopWidth) {
                    TextureRegion tileRegion = new TextureRegion(texture, x, y, tilewidth, tileheight);
                    addStaticTiledMapTile(tileSet, tileRegion, id2, offsetX, offsetY);
                    x += tilewidth + spacing;
                    id2++;
                    y = y;
                }
                y += tileheight + spacing;
                id = id2;
            }
            return;
        }
        Array.ArrayIterator<XmlReader.Element> it = tileElements.iterator();
        FileHandle image2 = image;
        while (it.hasNext()) {
            XmlReader.Element tileElement = it.next();
            XmlReader.Element imageElement = tileElement.getChildByName("image");
            if (imageElement != null) {
                String imageSource2 = imageElement.getAttribute("source");
                if (source != null) {
                    image2 = getRelativeFileHandle(getRelativeFileHandle(tmxFile, source), imageSource2);
                } else {
                    image2 = getRelativeFileHandle(tmxFile, imageSource2);
                }
            }
            String imageSource3 = image2.path();
            TextureRegion texture2 = imageResolver.getImage(imageSource3);
            int tileId = firstgid + tileElement.getIntAttribute("id");
            addStaticTiledMapTile(tileSet, texture2, tileId, offsetX, offsetY);
        }
    }
}