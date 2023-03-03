package com.badlogic.gdx.maps.tiled;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.TextureLoader;
import com.badlogic.gdx.assets.loaders.resolvers.InternalFileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.TextureAtlas;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.maps.ImageResolver;
import com.badlogic.gdx.maps.MapProperties;
import com.badlogic.gdx.maps.tiled.BaseTmxMapLoader;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.ObjectSet;
import com.badlogic.gdx.utils.XmlReader;

/* loaded from: classes.dex */
public class AtlasTmxMapLoader extends BaseTmxMapLoader<AtlasTiledMapLoaderParameters> {
    protected AtlasResolver atlasResolver;
    protected Array<Texture> trackedTextures;

    /* loaded from: classes.dex */
    public static class AtlasTiledMapLoaderParameters extends BaseTmxMapLoader.Parameters {
        public boolean forceTextureFilters = false;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public interface AtlasResolver extends ImageResolver {
        TextureAtlas getAtlas();

        /* loaded from: classes.dex */
        public static class DirectAtlasResolver implements AtlasResolver {
            private final TextureAtlas atlas;

            public DirectAtlasResolver(TextureAtlas atlas) {
                this.atlas = atlas;
            }

            @Override // com.badlogic.gdx.maps.tiled.AtlasTmxMapLoader.AtlasResolver
            public TextureAtlas getAtlas() {
                return this.atlas;
            }

            @Override // com.badlogic.gdx.maps.ImageResolver
            public TextureRegion getImage(String name) {
                return this.atlas.findRegion(name);
            }
        }

        /* loaded from: classes.dex */
        public static class AssetManagerAtlasResolver implements AtlasResolver {
            private final AssetManager assetManager;
            private final String atlasName;

            public AssetManagerAtlasResolver(AssetManager assetManager, String atlasName) {
                this.assetManager = assetManager;
                this.atlasName = atlasName;
            }

            @Override // com.badlogic.gdx.maps.tiled.AtlasTmxMapLoader.AtlasResolver
            public TextureAtlas getAtlas() {
                return (TextureAtlas) this.assetManager.get(this.atlasName, TextureAtlas.class);
            }

            @Override // com.badlogic.gdx.maps.ImageResolver
            public TextureRegion getImage(String name) {
                return getAtlas().findRegion(name);
            }
        }
    }

    public AtlasTmxMapLoader() {
        super(new InternalFileHandleResolver());
        this.trackedTextures = new Array<>();
    }

    public AtlasTmxMapLoader(FileHandleResolver resolver) {
        super(resolver);
        this.trackedTextures = new Array<>();
    }

    public TiledMap load(String fileName) {
        return load(fileName, new AtlasTiledMapLoaderParameters());
    }

    public TiledMap load(String fileName, AtlasTiledMapLoaderParameters parameter) {
        FileHandle tmxFile = resolve(fileName);
        this.root = this.xml.parse(tmxFile);
        FileHandle atlasFileHandle = getAtlasFileHandle(tmxFile);
        TextureAtlas atlas = new TextureAtlas(atlasFileHandle);
        this.atlasResolver = new AtlasResolver.DirectAtlasResolver(atlas);
        TiledMap map = loadTiledMap(tmxFile, parameter, this.atlasResolver);
        map.setOwnedResources(new Array<>(new TextureAtlas[]{atlas}));
        setTextureFilters(parameter.textureMinFilter, parameter.textureMagFilter);
        return map;
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public void loadAsync(AssetManager manager, String fileName, FileHandle tmxFile, AtlasTiledMapLoaderParameters parameter) {
        FileHandle atlasHandle = getAtlasFileHandle(tmxFile);
        this.atlasResolver = new AtlasResolver.AssetManagerAtlasResolver(manager, atlasHandle.path());
        this.map = loadTiledMap(tmxFile, parameter, this.atlasResolver);
    }

    @Override // com.badlogic.gdx.assets.loaders.AsynchronousAssetLoader
    public TiledMap loadSync(AssetManager manager, String fileName, FileHandle file, AtlasTiledMapLoaderParameters parameter) {
        if (parameter != null) {
            setTextureFilters(parameter.textureMinFilter, parameter.textureMagFilter);
        }
        return this.map;
    }

    @Override // com.badlogic.gdx.maps.tiled.BaseTmxMapLoader
    protected Array<AssetDescriptor> getDependencyAssetDescriptors(FileHandle tmxFile, TextureLoader.TextureParameter textureParameter) {
        Array<AssetDescriptor> descriptors = new Array<>();
        FileHandle atlasFileHandle = getAtlasFileHandle(tmxFile);
        if (atlasFileHandle != null) {
            descriptors.add(new AssetDescriptor(atlasFileHandle, TextureAtlas.class));
        }
        return descriptors;
    }

    @Override // com.badlogic.gdx.maps.tiled.BaseTmxMapLoader
    protected void addStaticTiles(FileHandle tmxFile, ImageResolver imageResolver, TiledMapTileSet tileSet, XmlReader.Element element, Array<XmlReader.Element> tileElements, String name, int firstgid, int tilewidth, int tileheight, int spacing, int margin, String source, int offsetX, int offsetY, String imageSource, int imageWidth, int imageHeight, FileHandle image) {
        XmlReader.Element imageElement;
        TextureAtlas atlas = this.atlasResolver.getAtlas();
        ObjectSet.ObjectSetIterator<Texture> it = atlas.getTextures().iterator();
        while (it.hasNext()) {
            Texture texture = it.next();
            this.trackedTextures.add(texture);
        }
        MapProperties props = tileSet.getProperties();
        props.put("imagesource", imageSource);
        props.put("imagewidth", Integer.valueOf(imageWidth));
        props.put("imageheight", Integer.valueOf(imageHeight));
        props.put("tilewidth", Integer.valueOf(tilewidth));
        props.put("tileheight", Integer.valueOf(tileheight));
        props.put("margin", Integer.valueOf(margin));
        props.put("spacing", Integer.valueOf(spacing));
        if (imageSource != null && imageSource.length() > 0) {
            int lastgid = (((imageWidth / tilewidth) * (imageHeight / tileheight)) + firstgid) - 1;
            Array.ArrayIterator<TextureAtlas.AtlasRegion> it2 = atlas.findRegions(name).iterator();
            while (it2.hasNext()) {
                TextureAtlas.AtlasRegion region = it2.next();
                if (region != null) {
                    int tileId = firstgid + region.index;
                    if (tileId >= firstgid && tileId <= lastgid) {
                        addStaticTiledMapTile(tileSet, region, tileId, offsetX, offsetY);
                    }
                }
            }
        }
        Array.ArrayIterator<XmlReader.Element> it3 = tileElements.iterator();
        while (it3.hasNext()) {
            XmlReader.Element tileElement = it3.next();
            int tileId2 = firstgid + tileElement.getIntAttribute("id", 0);
            TiledMapTile tile = tileSet.getTile(tileId2);
            if (tile == null && (imageElement = tileElement.getChildByName("image")) != null) {
                String regionName = imageElement.getAttribute("source");
                String regionName2 = regionName.substring(0, regionName.lastIndexOf(46));
                TextureAtlas.AtlasRegion region2 = atlas.findRegion(regionName2);
                if (region2 == null) {
                    throw new GdxRuntimeException("Tileset atlasRegion not found: " + regionName2);
                }
                addStaticTiledMapTile(tileSet, region2, tileId2, offsetX, offsetY);
            }
        }
    }

    protected FileHandle getAtlasFileHandle(FileHandle tmxFile) {
        XmlReader.Element properties = this.root.getChildByName("properties");
        String atlasFilePath = null;
        if (properties != null) {
            Array.ArrayIterator<XmlReader.Element> it = properties.getChildrenByName("property").iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                XmlReader.Element property = it.next();
                String name = property.getAttribute("name");
                if (name.startsWith("atlas")) {
                    atlasFilePath = property.getAttribute("value");
                    break;
                }
            }
        }
        if (atlasFilePath == null) {
            throw new GdxRuntimeException("The map is missing the 'atlas' property");
        }
        FileHandle fileHandle = getRelativeFileHandle(tmxFile, atlasFilePath);
        if (!fileHandle.exists()) {
            throw new GdxRuntimeException("The 'atlas' file could not be found: '" + atlasFilePath + "'");
        }
        return fileHandle;
    }

    protected void setTextureFilters(Texture.TextureFilter min, Texture.TextureFilter mag) {
        Array.ArrayIterator<Texture> it = this.trackedTextures.iterator();
        while (it.hasNext()) {
            Texture texture = it.next();
            texture.setFilter(min, mag);
        }
        this.trackedTextures.clear();
    }
}