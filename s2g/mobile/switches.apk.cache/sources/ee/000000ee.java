package com.badlogic.gdx.graphics;

import com.badlogic.gdx.Application;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.glutils.IndexArray;
import com.badlogic.gdx.graphics.glutils.IndexBufferObject;
import com.badlogic.gdx.graphics.glutils.IndexBufferObjectSubData;
import com.badlogic.gdx.graphics.glutils.IndexData;
import com.badlogic.gdx.graphics.glutils.InstanceBufferObject;
import com.badlogic.gdx.graphics.glutils.InstanceData;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.graphics.glutils.VertexArray;
import com.badlogic.gdx.graphics.glutils.VertexBufferObject;
import com.badlogic.gdx.graphics.glutils.VertexBufferObjectSubData;
import com.badlogic.gdx.graphics.glutils.VertexBufferObjectWithVAO;
import com.badlogic.gdx.graphics.glutils.VertexData;
import com.badlogic.gdx.math.Matrix3;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.Disposable;
import com.badlogic.gdx.utils.GdxRuntimeException;
import java.nio.FloatBuffer;
import java.nio.ShortBuffer;
import java.util.HashMap;
import java.util.Map;
import kotlin.UShort;

/* loaded from: classes.dex */
public class Mesh implements Disposable {
    static final Map<Application, Array<Mesh>> meshes = new HashMap();
    boolean autoBind;
    final IndexData indices;
    InstanceData instances;
    boolean isInstanced;
    final boolean isVertexArray;
    private final Vector3 tmpV;
    final VertexData vertices;

    /* loaded from: classes.dex */
    public enum VertexDataType {
        VertexArray,
        VertexBufferObject,
        VertexBufferObjectSubData,
        VertexBufferObjectWithVAO
    }

    protected Mesh(VertexData vertices, IndexData indices, boolean isVertexArray) {
        this.autoBind = true;
        this.isInstanced = false;
        this.tmpV = new Vector3();
        this.vertices = vertices;
        this.indices = indices;
        this.isVertexArray = isVertexArray;
        addManagedMesh(Gdx.app, this);
    }

    public Mesh(boolean isStatic, int maxVertices, int maxIndices, VertexAttribute... attributes) {
        this.autoBind = true;
        this.isInstanced = false;
        this.tmpV = new Vector3();
        this.vertices = makeVertexBuffer(isStatic, maxVertices, new VertexAttributes(attributes));
        this.indices = new IndexBufferObject(isStatic, maxIndices);
        this.isVertexArray = false;
        addManagedMesh(Gdx.app, this);
    }

    public Mesh(boolean isStatic, int maxVertices, int maxIndices, VertexAttributes attributes) {
        this.autoBind = true;
        this.isInstanced = false;
        this.tmpV = new Vector3();
        this.vertices = makeVertexBuffer(isStatic, maxVertices, attributes);
        this.indices = new IndexBufferObject(isStatic, maxIndices);
        this.isVertexArray = false;
        addManagedMesh(Gdx.app, this);
    }

    public Mesh(boolean staticVertices, boolean staticIndices, int maxVertices, int maxIndices, VertexAttributes attributes) {
        this.autoBind = true;
        this.isInstanced = false;
        this.tmpV = new Vector3();
        this.vertices = makeVertexBuffer(staticVertices, maxVertices, attributes);
        this.indices = new IndexBufferObject(staticIndices, maxIndices);
        this.isVertexArray = false;
        addManagedMesh(Gdx.app, this);
    }

    private VertexData makeVertexBuffer(boolean isStatic, int maxVertices, VertexAttributes vertexAttributes) {
        if (Gdx.gl30 != null) {
            return new VertexBufferObjectWithVAO(isStatic, maxVertices, vertexAttributes);
        }
        return new VertexBufferObject(isStatic, maxVertices, vertexAttributes);
    }

    public Mesh(VertexDataType type, boolean isStatic, int maxVertices, int maxIndices, VertexAttribute... attributes) {
        this(type, isStatic, maxVertices, maxIndices, new VertexAttributes(attributes));
    }

    /* renamed from: com.badlogic.gdx.graphics.Mesh$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType = new int[VertexDataType.values().length];

        static {
            try {
                $SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType[VertexDataType.VertexBufferObject.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType[VertexDataType.VertexBufferObjectSubData.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType[VertexDataType.VertexBufferObjectWithVAO.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType[VertexDataType.VertexArray.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    public Mesh(VertexDataType type, boolean isStatic, int maxVertices, int maxIndices, VertexAttributes attributes) {
        this.autoBind = true;
        this.isInstanced = false;
        this.tmpV = new Vector3();
        int i = AnonymousClass1.$SwitchMap$com$badlogic$gdx$graphics$Mesh$VertexDataType[type.ordinal()];
        if (i == 1) {
            this.vertices = new VertexBufferObject(isStatic, maxVertices, attributes);
            this.indices = new IndexBufferObject(isStatic, maxIndices);
            this.isVertexArray = false;
        } else if (i == 2) {
            this.vertices = new VertexBufferObjectSubData(isStatic, maxVertices, attributes);
            this.indices = new IndexBufferObjectSubData(isStatic, maxIndices);
            this.isVertexArray = false;
        } else if (i == 3) {
            this.vertices = new VertexBufferObjectWithVAO(isStatic, maxVertices, attributes);
            this.indices = new IndexBufferObjectSubData(isStatic, maxIndices);
            this.isVertexArray = false;
        } else {
            this.vertices = new VertexArray(maxVertices, attributes);
            this.indices = new IndexArray(maxIndices);
            this.isVertexArray = true;
        }
        addManagedMesh(Gdx.app, this);
    }

    public Mesh enableInstancedRendering(boolean isStatic, int maxInstances, VertexAttribute... attributes) {
        if (!this.isInstanced) {
            this.isInstanced = true;
            this.instances = new InstanceBufferObject(isStatic, maxInstances, attributes);
            return this;
        }
        throw new GdxRuntimeException("Trying to enable InstancedRendering on same Mesh instance twice. Use disableInstancedRendering to clean up old InstanceData first");
    }

    public Mesh disableInstancedRendering() {
        if (this.isInstanced) {
            this.isInstanced = false;
            this.instances.dispose();
            this.instances = null;
        }
        return this;
    }

    public Mesh setInstanceData(float[] instanceData, int offset, int count) {
        InstanceData instanceData2 = this.instances;
        if (instanceData2 != null) {
            instanceData2.setInstanceData(instanceData, offset, count);
            return this;
        }
        throw new GdxRuntimeException("An InstanceBufferObject must be set before setting instance data!");
    }

    public Mesh setInstanceData(float[] instanceData) {
        InstanceData instanceData2 = this.instances;
        if (instanceData2 != null) {
            instanceData2.setInstanceData(instanceData, 0, instanceData.length);
            return this;
        }
        throw new GdxRuntimeException("An InstanceBufferObject must be set before setting instance data!");
    }

    public Mesh setInstanceData(FloatBuffer instanceData, int count) {
        InstanceData instanceData2 = this.instances;
        if (instanceData2 != null) {
            instanceData2.setInstanceData(instanceData, count);
            return this;
        }
        throw new GdxRuntimeException("An InstanceBufferObject must be set before setting instance data!");
    }

    public Mesh setInstanceData(FloatBuffer instanceData) {
        InstanceData instanceData2 = this.instances;
        if (instanceData2 != null) {
            instanceData2.setInstanceData(instanceData, instanceData.limit());
            return this;
        }
        throw new GdxRuntimeException("An InstanceBufferObject must be set before setting instance data!");
    }

    public Mesh updateInstanceData(int targetOffset, float[] source) {
        return updateInstanceData(targetOffset, source, 0, source.length);
    }

    public Mesh updateInstanceData(int targetOffset, float[] source, int sourceOffset, int count) {
        this.instances.updateInstanceData(targetOffset, source, sourceOffset, count);
        return this;
    }

    public Mesh updateInstanceData(int targetOffset, FloatBuffer source) {
        return updateInstanceData(targetOffset, source, 0, source.limit());
    }

    public Mesh updateInstanceData(int targetOffset, FloatBuffer source, int sourceOffset, int count) {
        this.instances.updateInstanceData(targetOffset, source, sourceOffset, count);
        return this;
    }

    public Mesh setVertices(float[] vertices) {
        this.vertices.setVertices(vertices, 0, vertices.length);
        return this;
    }

    public boolean isInstanced() {
        return this.isInstanced;
    }

    public Mesh setVertices(float[] vertices, int offset, int count) {
        this.vertices.setVertices(vertices, offset, count);
        return this;
    }

    public Mesh updateVertices(int targetOffset, float[] source) {
        return updateVertices(targetOffset, source, 0, source.length);
    }

    public Mesh updateVertices(int targetOffset, float[] source, int sourceOffset, int count) {
        this.vertices.updateVertices(targetOffset, source, sourceOffset, count);
        return this;
    }

    public float[] getVertices(float[] vertices) {
        return getVertices(0, -1, vertices);
    }

    public float[] getVertices(int srcOffset, float[] vertices) {
        return getVertices(srcOffset, -1, vertices);
    }

    public float[] getVertices(int srcOffset, int count, float[] vertices) {
        return getVertices(srcOffset, count, vertices, 0);
    }

    public float[] getVertices(int srcOffset, int count, float[] vertices, int destOffset) {
        int max = (getNumVertices() * getVertexSize()) / 4;
        if (count == -1 && (count = max - srcOffset) > vertices.length - destOffset) {
            count = vertices.length - destOffset;
        }
        if (srcOffset < 0 || count <= 0 || srcOffset + count > max || destOffset < 0 || destOffset >= vertices.length) {
            throw new IndexOutOfBoundsException();
        }
        if (vertices.length - destOffset < count) {
            throw new IllegalArgumentException("not enough room in vertices array, has " + vertices.length + " floats, needs " + count);
        }
        int pos = getVerticesBuffer().position();
        getVerticesBuffer().position(srcOffset);
        getVerticesBuffer().get(vertices, destOffset, count);
        getVerticesBuffer().position(pos);
        return vertices;
    }

    public Mesh setIndices(short[] indices) {
        this.indices.setIndices(indices, 0, indices.length);
        return this;
    }

    public Mesh setIndices(short[] indices, int offset, int count) {
        this.indices.setIndices(indices, offset, count);
        return this;
    }

    public void getIndices(short[] indices) {
        getIndices(indices, 0);
    }

    public void getIndices(short[] indices, int destOffset) {
        getIndices(0, indices, destOffset);
    }

    public void getIndices(int srcOffset, short[] indices, int destOffset) {
        getIndices(srcOffset, -1, indices, destOffset);
    }

    public void getIndices(int srcOffset, int count, short[] indices, int destOffset) {
        int max = getNumIndices();
        if (count < 0) {
            count = max - srcOffset;
        }
        if (srcOffset < 0 || srcOffset >= max || srcOffset + count > max) {
            throw new IllegalArgumentException("Invalid range specified, offset: " + srcOffset + ", count: " + count + ", max: " + max);
        } else if (indices.length - destOffset < count) {
            throw new IllegalArgumentException("not enough room in indices array, has " + indices.length + " shorts, needs " + count);
        } else {
            int pos = getIndicesBuffer().position();
            getIndicesBuffer().position(srcOffset);
            getIndicesBuffer().get(indices, destOffset, count);
            getIndicesBuffer().position(pos);
        }
    }

    public int getNumIndices() {
        return this.indices.getNumIndices();
    }

    public int getNumVertices() {
        return this.vertices.getNumVertices();
    }

    public int getMaxVertices() {
        return this.vertices.getNumMaxVertices();
    }

    public int getMaxIndices() {
        return this.indices.getNumMaxIndices();
    }

    public int getVertexSize() {
        return this.vertices.getAttributes().vertexSize;
    }

    public void setAutoBind(boolean autoBind) {
        this.autoBind = autoBind;
    }

    public void bind(ShaderProgram shader) {
        bind(shader, null);
    }

    public void bind(ShaderProgram shader, int[] locations) {
        this.vertices.bind(shader, locations);
        InstanceData instanceData = this.instances;
        if (instanceData != null && instanceData.getNumInstances() > 0) {
            this.instances.bind(shader, locations);
        }
        if (this.indices.getNumIndices() > 0) {
            this.indices.bind();
        }
    }

    public void unbind(ShaderProgram shader) {
        unbind(shader, null);
    }

    public void unbind(ShaderProgram shader, int[] locations) {
        this.vertices.unbind(shader, locations);
        InstanceData instanceData = this.instances;
        if (instanceData != null && instanceData.getNumInstances() > 0) {
            this.instances.unbind(shader, locations);
        }
        if (this.indices.getNumIndices() > 0) {
            this.indices.unbind();
        }
    }

    public void render(ShaderProgram shader, int primitiveType) {
        render(shader, primitiveType, 0, this.indices.getNumMaxIndices() > 0 ? getNumIndices() : getNumVertices(), this.autoBind);
    }

    public void render(ShaderProgram shader, int primitiveType, int offset, int count) {
        render(shader, primitiveType, offset, count, this.autoBind);
    }

    public void render(ShaderProgram shader, int primitiveType, int offset, int count, boolean autoBind) {
        if (count == 0) {
            return;
        }
        if (autoBind) {
            bind(shader);
        }
        if (this.isVertexArray) {
            if (this.indices.getNumIndices() > 0) {
                ShortBuffer buffer = this.indices.getBuffer();
                int oldPosition = buffer.position();
                int oldLimit = buffer.limit();
                buffer.position(offset);
                buffer.limit(offset + count);
                Gdx.gl20.glDrawElements(primitiveType, count, GL20.GL_UNSIGNED_SHORT, buffer);
                buffer.position(oldPosition);
                buffer.limit(oldLimit);
            } else {
                Gdx.gl20.glDrawArrays(primitiveType, offset, count);
            }
        } else {
            int numInstances = this.isInstanced ? this.instances.getNumInstances() : 0;
            if (this.indices.getNumIndices() > 0) {
                if (count + offset > this.indices.getNumMaxIndices()) {
                    throw new GdxRuntimeException("Mesh attempting to access memory outside of the index buffer (count: " + count + ", offset: " + offset + ", max: " + this.indices.getNumMaxIndices() + ")");
                } else if (this.isInstanced && numInstances > 0) {
                    Gdx.gl30.glDrawElementsInstanced(primitiveType, count, GL20.GL_UNSIGNED_SHORT, offset * 2, numInstances);
                } else {
                    Gdx.gl20.glDrawElements(primitiveType, count, GL20.GL_UNSIGNED_SHORT, offset * 2);
                }
            } else if (this.isInstanced && numInstances > 0) {
                Gdx.gl30.glDrawArraysInstanced(primitiveType, offset, count, numInstances);
            } else {
                Gdx.gl20.glDrawArrays(primitiveType, offset, count);
            }
        }
        if (autoBind) {
            unbind(shader);
        }
    }

    @Override // com.badlogic.gdx.utils.Disposable
    public void dispose() {
        if (meshes.get(Gdx.app) != null) {
            meshes.get(Gdx.app).removeValue(this, true);
        }
        this.vertices.dispose();
        InstanceData instanceData = this.instances;
        if (instanceData != null) {
            instanceData.dispose();
        }
        this.indices.dispose();
    }

    public VertexAttribute getVertexAttribute(int usage) {
        VertexAttributes attributes = this.vertices.getAttributes();
        int len = attributes.size();
        for (int i = 0; i < len; i++) {
            if (attributes.get(i).usage == usage) {
                return attributes.get(i);
            }
        }
        return null;
    }

    public VertexAttributes getVertexAttributes() {
        return this.vertices.getAttributes();
    }

    public FloatBuffer getVerticesBuffer() {
        return this.vertices.getBuffer();
    }

    public BoundingBox calculateBoundingBox() {
        BoundingBox bbox = new BoundingBox();
        calculateBoundingBox(bbox);
        return bbox;
    }

    public void calculateBoundingBox(BoundingBox bbox) {
        int numVertices = getNumVertices();
        if (numVertices == 0) {
            throw new GdxRuntimeException("No vertices defined");
        }
        FloatBuffer verts = this.vertices.getBuffer();
        bbox.inf();
        VertexAttribute posAttrib = getVertexAttribute(1);
        int offset = posAttrib.offset / 4;
        int vertexSize = this.vertices.getAttributes().vertexSize / 4;
        int idx = offset;
        int i = posAttrib.numComponents;
        if (i == 1) {
            for (int i2 = 0; i2 < numVertices; i2++) {
                bbox.ext(verts.get(idx), 0.0f, 0.0f);
                idx += vertexSize;
            }
        } else if (i == 2) {
            for (int i3 = 0; i3 < numVertices; i3++) {
                bbox.ext(verts.get(idx), verts.get(idx + 1), 0.0f);
                idx += vertexSize;
            }
        } else if (i == 3) {
            for (int i4 = 0; i4 < numVertices; i4++) {
                bbox.ext(verts.get(idx), verts.get(idx + 1), verts.get(idx + 2));
                idx += vertexSize;
            }
        }
    }

    public BoundingBox calculateBoundingBox(BoundingBox out, int offset, int count) {
        return extendBoundingBox(out.inf(), offset, count);
    }

    public BoundingBox calculateBoundingBox(BoundingBox out, int offset, int count, Matrix4 transform) {
        return extendBoundingBox(out.inf(), offset, count, transform);
    }

    public BoundingBox extendBoundingBox(BoundingBox out, int offset, int count) {
        return extendBoundingBox(out, offset, count, null);
    }

    public BoundingBox extendBoundingBox(BoundingBox out, int offset, int count, Matrix4 transform) {
        int numIndices = getNumIndices();
        int numVertices = getNumVertices();
        int max = numIndices == 0 ? numVertices : numIndices;
        if (offset < 0 || count < 1 || offset + count > max) {
            throw new GdxRuntimeException("Invalid part specified ( offset=" + offset + ", count=" + count + ", max=" + max + " )");
        }
        FloatBuffer verts = this.vertices.getBuffer();
        ShortBuffer index = this.indices.getBuffer();
        VertexAttribute posAttrib = getVertexAttribute(1);
        int posoff = posAttrib.offset / 4;
        int vertexSize = this.vertices.getAttributes().vertexSize / 4;
        int end = offset + count;
        int i = posAttrib.numComponents;
        if (i != 1) {
            if (i != 2) {
                if (i == 3) {
                    if (numIndices > 0) {
                        int i2 = offset;
                        while (i2 < end) {
                            int idx = ((index.get(i2) & UShort.MAX_VALUE) * vertexSize) + posoff;
                            VertexAttribute posAttrib2 = posAttrib;
                            int max2 = max;
                            this.tmpV.set(verts.get(idx), verts.get(idx + 1), verts.get(idx + 2));
                            if (transform != null) {
                                this.tmpV.mul(transform);
                            }
                            out.ext(this.tmpV);
                            i2++;
                            posAttrib = posAttrib2;
                            max = max2;
                        }
                    } else {
                        for (int i3 = offset; i3 < end; i3++) {
                            int idx2 = (i3 * vertexSize) + posoff;
                            this.tmpV.set(verts.get(idx2), verts.get(idx2 + 1), verts.get(idx2 + 2));
                            if (transform != null) {
                                this.tmpV.mul(transform);
                            }
                            out.ext(this.tmpV);
                        }
                    }
                }
            } else if (numIndices > 0) {
                for (int i4 = offset; i4 < end; i4++) {
                    int idx3 = ((index.get(i4) & UShort.MAX_VALUE) * vertexSize) + posoff;
                    this.tmpV.set(verts.get(idx3), verts.get(idx3 + 1), 0.0f);
                    if (transform != null) {
                        this.tmpV.mul(transform);
                    }
                    out.ext(this.tmpV);
                }
            } else {
                for (int i5 = offset; i5 < end; i5++) {
                    int idx4 = (i5 * vertexSize) + posoff;
                    this.tmpV.set(verts.get(idx4), verts.get(idx4 + 1), 0.0f);
                    if (transform != null) {
                        this.tmpV.mul(transform);
                    }
                    out.ext(this.tmpV);
                }
            }
        } else if (numIndices > 0) {
            for (int i6 = offset; i6 < end; i6++) {
                int idx5 = ((index.get(i6) & UShort.MAX_VALUE) * vertexSize) + posoff;
                this.tmpV.set(verts.get(idx5), 0.0f, 0.0f);
                if (transform != null) {
                    this.tmpV.mul(transform);
                }
                out.ext(this.tmpV);
            }
        } else {
            for (int i7 = offset; i7 < end; i7++) {
                int idx6 = (i7 * vertexSize) + posoff;
                this.tmpV.set(verts.get(idx6), 0.0f, 0.0f);
                if (transform != null) {
                    this.tmpV.mul(transform);
                }
                out.ext(this.tmpV);
            }
        }
        return out;
    }

    public float calculateRadiusSquared(float centerX, float centerY, float centerZ, int offset, int count, Matrix4 transform) {
        int numIndices = getNumIndices();
        if (offset < 0 || count < 1 || offset + count > numIndices) {
            throw new GdxRuntimeException("Not enough indices");
        }
        FloatBuffer verts = this.vertices.getBuffer();
        ShortBuffer index = this.indices.getBuffer();
        VertexAttribute posAttrib = getVertexAttribute(1);
        int posoff = posAttrib.offset / 4;
        int vertexSize = this.vertices.getAttributes().vertexSize / 4;
        int end = offset + count;
        float result = 0.0f;
        int i = posAttrib.numComponents;
        if (i == 1) {
            for (int i2 = offset; i2 < end; i2++) {
                this.tmpV.set(verts.get(((index.get(i2) & UShort.MAX_VALUE) * vertexSize) + posoff), 0.0f, 0.0f);
                if (transform != null) {
                    this.tmpV.mul(transform);
                }
                float r = this.tmpV.sub(centerX, centerY, centerZ).len2();
                if (r > result) {
                    result = r;
                }
            }
        } else if (i == 2) {
            for (int i3 = offset; i3 < end; i3++) {
                int idx = ((index.get(i3) & UShort.MAX_VALUE) * vertexSize) + posoff;
                this.tmpV.set(verts.get(idx), verts.get(idx + 1), 0.0f);
                if (transform != null) {
                    this.tmpV.mul(transform);
                }
                float r2 = this.tmpV.sub(centerX, centerY, centerZ).len2();
                if (r2 > result) {
                    result = r2;
                }
            }
        } else if (i == 3) {
            int i4 = offset;
            while (i4 < end) {
                int idx2 = ((index.get(i4) & UShort.MAX_VALUE) * vertexSize) + posoff;
                int numIndices2 = numIndices;
                VertexAttribute posAttrib2 = posAttrib;
                int posoff2 = posoff;
                this.tmpV.set(verts.get(idx2), verts.get(idx2 + 1), verts.get(idx2 + 2));
                if (transform != null) {
                    this.tmpV.mul(transform);
                }
                float r3 = this.tmpV.sub(centerX, centerY, centerZ).len2();
                if (r3 > result) {
                    result = r3;
                }
                i4++;
                numIndices = numIndices2;
                posAttrib = posAttrib2;
                posoff = posoff2;
            }
        }
        return result;
    }

    public float calculateRadius(float centerX, float centerY, float centerZ, int offset, int count, Matrix4 transform) {
        return (float) Math.sqrt(calculateRadiusSquared(centerX, centerY, centerZ, offset, count, transform));
    }

    public float calculateRadius(Vector3 center, int offset, int count, Matrix4 transform) {
        return calculateRadius(center.x, center.y, center.z, offset, count, transform);
    }

    public float calculateRadius(float centerX, float centerY, float centerZ, int offset, int count) {
        return calculateRadius(centerX, centerY, centerZ, offset, count, null);
    }

    public float calculateRadius(Vector3 center, int offset, int count) {
        return calculateRadius(center.x, center.y, center.z, offset, count, null);
    }

    public float calculateRadius(float centerX, float centerY, float centerZ) {
        return calculateRadius(centerX, centerY, centerZ, 0, getNumIndices(), null);
    }

    public float calculateRadius(Vector3 center) {
        return calculateRadius(center.x, center.y, center.z, 0, getNumIndices(), null);
    }

    public ShortBuffer getIndicesBuffer() {
        return this.indices.getBuffer();
    }

    private static void addManagedMesh(Application app, Mesh mesh) {
        Array<Mesh> managedResources = meshes.get(app);
        if (managedResources == null) {
            managedResources = new Array<>();
        }
        managedResources.add(mesh);
        meshes.put(app, managedResources);
    }

    public static void invalidateAllMeshes(Application app) {
        Array<Mesh> meshesArray = meshes.get(app);
        if (meshesArray == null) {
            return;
        }
        for (int i = 0; i < meshesArray.size; i++) {
            meshesArray.get(i).vertices.invalidate();
            meshesArray.get(i).indices.invalidate();
        }
    }

    public static void clearAllMeshes(Application app) {
        meshes.remove(app);
    }

    public static String getManagedStatus() {
        StringBuilder builder = new StringBuilder();
        builder.append("Managed meshes/app: { ");
        for (Application app : meshes.keySet()) {
            builder.append(meshes.get(app).size);
            builder.append(" ");
        }
        builder.append("}");
        return builder.toString();
    }

    public void scale(float scaleX, float scaleY, float scaleZ) {
        VertexAttribute posAttr = getVertexAttribute(1);
        int offset = posAttr.offset / 4;
        int numComponents = posAttr.numComponents;
        int numVertices = getNumVertices();
        int vertexSize = getVertexSize() / 4;
        float[] vertices = new float[numVertices * vertexSize];
        getVertices(vertices);
        int idx = offset;
        if (numComponents == 1) {
            for (int i = 0; i < numVertices; i++) {
                vertices[idx] = vertices[idx] * scaleX;
                idx += vertexSize;
            }
        } else if (numComponents == 2) {
            for (int i2 = 0; i2 < numVertices; i2++) {
                vertices[idx] = vertices[idx] * scaleX;
                int i3 = idx + 1;
                vertices[i3] = vertices[i3] * scaleY;
                idx += vertexSize;
            }
        } else if (numComponents == 3) {
            for (int i4 = 0; i4 < numVertices; i4++) {
                vertices[idx] = vertices[idx] * scaleX;
                int i5 = idx + 1;
                vertices[i5] = vertices[i5] * scaleY;
                int i6 = idx + 2;
                vertices[i6] = vertices[i6] * scaleZ;
                idx += vertexSize;
            }
        }
        setVertices(vertices);
    }

    public void transform(Matrix4 matrix) {
        transform(matrix, 0, getNumVertices());
    }

    public void transform(Matrix4 matrix, int start, int count) {
        VertexAttribute posAttr = getVertexAttribute(1);
        int posOffset = posAttr.offset / 4;
        int stride = getVertexSize() / 4;
        int numComponents = posAttr.numComponents;
        getNumVertices();
        float[] vertices = new float[count * stride];
        getVertices(start * stride, count * stride, vertices);
        transform(matrix, vertices, stride, posOffset, numComponents, 0, count);
        updateVertices(start * stride, vertices);
    }

    public static void transform(Matrix4 matrix, float[] vertices, int vertexSize, int offset, int dimensions, int start, int count) {
        if (offset < 0 || dimensions < 1 || offset + dimensions > vertexSize) {
            throw new IndexOutOfBoundsException();
        }
        if (start < 0 || count < 1 || (start + count) * vertexSize > vertices.length) {
            throw new IndexOutOfBoundsException("start = " + start + ", count = " + count + ", vertexSize = " + vertexSize + ", length = " + vertices.length);
        }
        Vector3 tmp = new Vector3();
        int idx = (start * vertexSize) + offset;
        if (dimensions == 1) {
            for (int i = 0; i < count; i++) {
                tmp.set(vertices[idx], 0.0f, 0.0f).mul(matrix);
                vertices[idx] = tmp.x;
                idx += vertexSize;
            }
        } else if (dimensions == 2) {
            for (int i2 = 0; i2 < count; i2++) {
                tmp.set(vertices[idx], vertices[idx + 1], 0.0f).mul(matrix);
                vertices[idx] = tmp.x;
                vertices[idx + 1] = tmp.y;
                idx += vertexSize;
            }
        } else if (dimensions == 3) {
            for (int i3 = 0; i3 < count; i3++) {
                tmp.set(vertices[idx], vertices[idx + 1], vertices[idx + 2]).mul(matrix);
                vertices[idx] = tmp.x;
                vertices[idx + 1] = tmp.y;
                vertices[idx + 2] = tmp.z;
                idx += vertexSize;
            }
        }
    }

    public void transformUV(Matrix3 matrix) {
        transformUV(matrix, 0, getNumVertices());
    }

    protected void transformUV(Matrix3 matrix, int start, int count) {
        VertexAttribute posAttr = getVertexAttribute(16);
        int offset = posAttr.offset / 4;
        int vertexSize = getVertexSize() / 4;
        int numVertices = getNumVertices();
        float[] vertices = new float[numVertices * vertexSize];
        getVertices(0, vertices.length, vertices);
        transformUV(matrix, vertices, vertexSize, offset, start, count);
        setVertices(vertices, 0, vertices.length);
    }

    public static void transformUV(Matrix3 matrix, float[] vertices, int vertexSize, int offset, int start, int count) {
        if (start < 0 || count < 1 || (start + count) * vertexSize > vertices.length) {
            throw new IndexOutOfBoundsException("start = " + start + ", count = " + count + ", vertexSize = " + vertexSize + ", length = " + vertices.length);
        }
        Vector2 tmp = new Vector2();
        int idx = (start * vertexSize) + offset;
        for (int i = 0; i < count; i++) {
            tmp.set(vertices[idx], vertices[idx + 1]).mul(matrix);
            vertices[idx] = tmp.x;
            vertices[idx + 1] = tmp.y;
            idx += vertexSize;
        }
    }

    public Mesh copy(boolean isStatic, boolean removeDuplicates, int[] usage) {
        Mesh result;
        int vertexSize;
        int vertexSize2 = getVertexSize() / 4;
        int numVertices = getNumVertices();
        float[] vertices = new float[numVertices * vertexSize2];
        getVertices(0, vertices.length, vertices);
        short[] checks = null;
        VertexAttribute[] attrs = null;
        short newVertexSize = 0;
        if (usage != null) {
            int size = 0;
            int as = 0;
            for (int i = 0; i < usage.length; i++) {
                if (getVertexAttribute(usage[i]) != null) {
                    size += getVertexAttribute(usage[i]).numComponents;
                    as++;
                }
            }
            if (size > 0) {
                attrs = new VertexAttribute[as];
                checks = new short[size];
                int idx = -1;
                int ai = -1;
                for (int i2 : usage) {
                    VertexAttribute a = getVertexAttribute(i2);
                    if (a != null) {
                        int idx2 = idx;
                        for (int idx3 = 0; idx3 < a.numComponents; idx3++) {
                            idx2++;
                            checks[idx2] = (short) (a.offset + idx3);
                        }
                        ai++;
                        attrs[ai] = a.copy();
                        newVertexSize += a.numComponents;
                        idx = idx2;
                    }
                }
            }
        }
        if (checks == null) {
            checks = new short[vertexSize2];
            for (short i3 = 0; i3 < vertexSize2; i3 = (short) (i3 + 1)) {
                checks[i3] = i3;
            }
            newVertexSize = vertexSize2;
        }
        int numIndices = getNumIndices();
        short[] indices = null;
        if (numIndices > 0) {
            indices = new short[numIndices];
            getIndices(indices);
            if (removeDuplicates || newVertexSize != vertexSize2) {
                float[] tmp = new float[vertices.length];
                int size2 = 0;
                int i4 = 0;
                while (i4 < numIndices) {
                    int idx1 = indices[i4] * vertexSize2;
                    short j = -1;
                    if (removeDuplicates) {
                        short newIndex = -1;
                        for (short j2 = 0; j2 < size2 && newIndex < 0; j2 = (short) (j2 + 1)) {
                            int idx22 = j2 * newVertexSize;
                            boolean found = true;
                            for (int k = 0; k < checks.length && found; k++) {
                                if (tmp[idx22 + k] != vertices[idx1 + checks[k]]) {
                                    found = false;
                                }
                            }
                            if (found) {
                                newIndex = j2;
                            }
                        }
                        j = newIndex;
                    }
                    if (j > 0) {
                        indices[i4] = j;
                        vertexSize = vertexSize2;
                    } else {
                        int idx4 = size2 * newVertexSize;
                        int j3 = 0;
                        while (true) {
                            vertexSize = vertexSize2;
                            if (j3 >= checks.length) {
                                break;
                            }
                            tmp[idx4 + j3] = vertices[idx1 + checks[j3]];
                            j3++;
                            vertexSize2 = vertexSize;
                        }
                        indices[i4] = (short) size2;
                        size2++;
                    }
                    i4++;
                    vertexSize2 = vertexSize;
                }
                vertices = tmp;
                numVertices = size2;
            }
        }
        if (attrs == null) {
            result = new Mesh(isStatic, numVertices, indices == null ? 0 : indices.length, getVertexAttributes());
        } else {
            result = new Mesh(isStatic, numVertices, indices == null ? 0 : indices.length, attrs);
        }
        result.setVertices(vertices, 0, numVertices * newVertexSize);
        if (indices != null) {
            result.setIndices(indices);
        }
        return result;
    }

    public Mesh copy(boolean isStatic) {
        return copy(isStatic, false, null);
    }
}