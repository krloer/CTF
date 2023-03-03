package com.badlogic.gdx.graphics.g2d;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetLoaderParameters;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.assets.loaders.FileHandleResolver;
import com.badlogic.gdx.assets.loaders.SynchronousAssetLoader;
import com.badlogic.gdx.assets.loaders.resolvers.InternalFileHandleResolver;
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.math.EarClippingTriangulator;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.StreamUtils;
import java.io.BufferedReader;
import java.io.IOException;

/* loaded from: classes.dex */
public class PolygonRegionLoader extends SynchronousAssetLoader<PolygonRegion, PolygonRegionParameters> {
    private PolygonRegionParameters defaultParameters;
    private EarClippingTriangulator triangulator;

    /* loaded from: classes.dex */
    public static class PolygonRegionParameters extends AssetLoaderParameters<PolygonRegion> {
        public String texturePrefix = "i ";
        public int readerBuffer = GL20.GL_STENCIL_BUFFER_BIT;
        public String[] textureExtensions = {"png", "PNG", "jpeg", "JPEG", "jpg", "JPG", "cim", "CIM", "etc1", "ETC1", "ktx", "KTX", "zktx", "ZKTX"};
    }

    public PolygonRegionLoader() {
        this(new InternalFileHandleResolver());
    }

    public PolygonRegionLoader(FileHandleResolver resolver) {
        super(resolver);
        this.defaultParameters = new PolygonRegionParameters();
        this.triangulator = new EarClippingTriangulator();
    }

    @Override // com.badlogic.gdx.assets.loaders.SynchronousAssetLoader
    public PolygonRegion load(AssetManager manager, String fileName, FileHandle file, PolygonRegionParameters parameter) {
        Texture texture = (Texture) manager.get(manager.getDependencies(fileName).first());
        return load(new TextureRegion(texture), file);
    }

    @Override // com.badlogic.gdx.assets.loaders.AssetLoader
    public Array<AssetDescriptor> getDependencies(String fileName, FileHandle file, PolygonRegionParameters params) {
        String[] strArr;
        if (params == null) {
            params = this.defaultParameters;
        }
        String image = null;
        try {
            BufferedReader reader = file.reader(params.readerBuffer);
            String line = reader.readLine();
            while (true) {
                if (line != null) {
                    if (!line.startsWith(params.texturePrefix)) {
                        line = reader.readLine();
                    } else {
                        image = line.substring(params.texturePrefix.length());
                        break;
                    }
                } else {
                    break;
                }
            }
            reader.close();
            if (image == null && params.textureExtensions != null) {
                for (String extension : params.textureExtensions) {
                    FileHandle sibling = file.sibling(file.nameWithoutExtension().concat("." + extension));
                    if (sibling.exists()) {
                        image = sibling.name();
                    }
                }
            }
            if (image != null) {
                Array<AssetDescriptor> deps = new Array<>(1);
                deps.add(new AssetDescriptor(file.sibling(image), Texture.class));
                return deps;
            }
            return null;
        } catch (IOException e) {
            throw new GdxRuntimeException("Error reading " + fileName, e);
        }
    }

    public PolygonRegion load(TextureRegion textureRegion, FileHandle file) {
        String line;
        BufferedReader reader = file.reader(256);
        do {
            try {
                try {
                    line = reader.readLine();
                    if (line == null) {
                        StreamUtils.closeQuietly(reader);
                        throw new GdxRuntimeException("Polygon shape not found: " + file);
                    }
                } catch (IOException ex) {
                    throw new GdxRuntimeException("Error reading polygon shape file: " + file, ex);
                }
            } finally {
                StreamUtils.closeQuietly(reader);
            }
        } while (!line.startsWith("s"));
        String[] polygonStrings = line.substring(1).trim().split(",");
        float[] vertices = new float[polygonStrings.length];
        int n = vertices.length;
        for (int i = 0; i < n; i++) {
            vertices[i] = Float.parseFloat(polygonStrings[i]);
        }
        return new PolygonRegion(textureRegion, vertices, this.triangulator.computeTriangles(vertices).toArray());
    }
}