package com.badlogic.gdx.graphics.g3d.utils;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.VertexAttribute;
import com.badlogic.gdx.graphics.VertexAttributes;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.graphics.g3d.model.MeshPart;
import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.ArrowShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.BoxShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.CapsuleShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.ConeShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.CylinderShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.EllipseShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.PatchShapeBuilder;
import com.badlogic.gdx.graphics.g3d.utils.shapebuilders.SphereShapeBuilder;
import com.badlogic.gdx.graphics.glutils.ShaderProgram;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Matrix3;
import com.badlogic.gdx.math.Matrix4;
import com.badlogic.gdx.math.Vector2;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.math.collision.BoundingBox;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FloatArray;
import com.badlogic.gdx.utils.GdxRuntimeException;
import com.badlogic.gdx.utils.IntIntMap;
import com.badlogic.gdx.utils.ShortArray;
import kotlin.UShort;

/* loaded from: classes.dex */
public class MeshBuilder implements MeshPartBuilder {
    public static final int MAX_INDEX = 65535;
    public static final int MAX_VERTICES = 65536;
    private VertexAttributes attributes;
    private int biNorOffset;
    private int colOffset;
    private int colSize;
    private int cpOffset;
    private int istart;
    private int norOffset;
    private MeshPart part;
    private int posOffset;
    private int posSize;
    private int primitiveType;
    private int stride;
    private int tangentOffset;
    private int uvOffset;
    private float[] vertex;
    private int vindex;
    private static final ShortArray tmpIndices = new ShortArray();
    private static final FloatArray tmpVertices = new FloatArray();
    private static final Vector3 vTmp = new Vector3();
    private static IntIntMap indicesMap = null;
    private final MeshPartBuilder.VertexInfo vertTmp1 = new MeshPartBuilder.VertexInfo();
    private final MeshPartBuilder.VertexInfo vertTmp2 = new MeshPartBuilder.VertexInfo();
    private final MeshPartBuilder.VertexInfo vertTmp3 = new MeshPartBuilder.VertexInfo();
    private final MeshPartBuilder.VertexInfo vertTmp4 = new MeshPartBuilder.VertexInfo();
    private final Color tempC1 = new Color();
    private FloatArray vertices = new FloatArray();
    private ShortArray indices = new ShortArray();
    private Array<MeshPart> parts = new Array<>();
    private final Color color = new Color(Color.WHITE);
    private boolean hasColor = false;
    private float uOffset = 0.0f;
    private float uScale = 1.0f;
    private float vOffset = 0.0f;
    private float vScale = 1.0f;
    private boolean hasUVTransform = false;
    private boolean vertexTransformationEnabled = false;
    private final Matrix4 positionTransform = new Matrix4();
    private final Matrix3 normalTransform = new Matrix3();
    private final BoundingBox bounds = new BoundingBox();
    private int lastIndex = -1;
    private final Vector3 tmpNormal = new Vector3();

    public static VertexAttributes createAttributes(long usage) {
        Array<VertexAttribute> attrs = new Array<>();
        if ((usage & 1) == 1) {
            attrs.add(new VertexAttribute(1, 3, ShaderProgram.POSITION_ATTRIBUTE));
        }
        if ((usage & 2) == 2) {
            attrs.add(new VertexAttribute(2, 4, ShaderProgram.COLOR_ATTRIBUTE));
        }
        if ((usage & 4) == 4) {
            attrs.add(new VertexAttribute(4, 4, ShaderProgram.COLOR_ATTRIBUTE));
        }
        if ((usage & 8) == 8) {
            attrs.add(new VertexAttribute(8, 3, ShaderProgram.NORMAL_ATTRIBUTE));
        }
        if ((usage & 16) == 16) {
            attrs.add(new VertexAttribute(16, 2, "a_texCoord0"));
        }
        VertexAttribute[] attributes = new VertexAttribute[attrs.size];
        for (int i = 0; i < attributes.length; i++) {
            attributes[i] = attrs.get(i);
        }
        return new VertexAttributes(attributes);
    }

    public void begin(long attributes) {
        begin(createAttributes(attributes), -1);
    }

    public void begin(VertexAttributes attributes) {
        begin(attributes, -1);
    }

    public void begin(long attributes, int primitiveType) {
        begin(createAttributes(attributes), primitiveType);
    }

    public void begin(VertexAttributes attributes, int primitiveType) {
        if (this.attributes != null) {
            throw new RuntimeException("Call end() first");
        }
        this.attributes = attributes;
        this.vertices.clear();
        this.indices.clear();
        this.parts.clear();
        this.vindex = 0;
        this.lastIndex = -1;
        this.istart = 0;
        this.part = null;
        this.stride = attributes.vertexSize / 4;
        float[] fArr = this.vertex;
        if (fArr == null || fArr.length < this.stride) {
            this.vertex = new float[this.stride];
        }
        VertexAttribute a = attributes.findByUsage(1);
        if (a == null) {
            throw new GdxRuntimeException("Cannot build mesh without position attribute");
        }
        this.posOffset = a.offset / 4;
        this.posSize = a.numComponents;
        VertexAttribute a2 = attributes.findByUsage(8);
        this.norOffset = a2 == null ? -1 : a2.offset / 4;
        VertexAttribute a3 = attributes.findByUsage(256);
        this.biNorOffset = a3 == null ? -1 : a3.offset / 4;
        VertexAttribute a4 = attributes.findByUsage(128);
        this.tangentOffset = a4 == null ? -1 : a4.offset / 4;
        VertexAttribute a5 = attributes.findByUsage(2);
        this.colOffset = a5 == null ? -1 : a5.offset / 4;
        this.colSize = a5 != null ? a5.numComponents : 0;
        VertexAttribute a6 = attributes.findByUsage(4);
        this.cpOffset = a6 == null ? -1 : a6.offset / 4;
        VertexAttribute a7 = attributes.findByUsage(16);
        this.uvOffset = a7 != null ? a7.offset / 4 : -1;
        setColor(null);
        setVertexTransform(null);
        setUVRange(null);
        this.primitiveType = primitiveType;
        this.bounds.inf();
    }

    private void endpart() {
        MeshPart meshPart = this.part;
        if (meshPart != null) {
            this.bounds.getCenter(meshPart.center);
            this.bounds.getDimensions(this.part.halfExtents).scl(0.5f);
            MeshPart meshPart2 = this.part;
            meshPart2.radius = meshPart2.halfExtents.len();
            this.bounds.inf();
            MeshPart meshPart3 = this.part;
            meshPart3.offset = this.istart;
            meshPart3.size = this.indices.size - this.istart;
            this.istart = this.indices.size;
            this.part = null;
        }
    }

    public MeshPart part(String id, int primitiveType) {
        return part(id, primitiveType, new MeshPart());
    }

    public MeshPart part(String id, int primitiveType, MeshPart meshPart) {
        if (this.attributes == null) {
            throw new RuntimeException("Call begin() first");
        }
        endpart();
        this.part = meshPart;
        MeshPart meshPart2 = this.part;
        meshPart2.id = id;
        meshPart2.primitiveType = primitiveType;
        this.primitiveType = primitiveType;
        this.parts.add(meshPart2);
        setColor(null);
        setVertexTransform(null);
        setUVRange(null);
        return this.part;
    }

    public Mesh end(Mesh mesh) {
        endpart();
        VertexAttributes vertexAttributes = this.attributes;
        if (vertexAttributes == null) {
            throw new GdxRuntimeException("Call begin() first");
        }
        if (!vertexAttributes.equals(mesh.getVertexAttributes())) {
            throw new GdxRuntimeException("Mesh attributes don't match");
        }
        if (mesh.getMaxVertices() * this.stride < this.vertices.size) {
            throw new GdxRuntimeException("Mesh can't hold enough vertices: " + mesh.getMaxVertices() + " * " + this.stride + " < " + this.vertices.size);
        } else if (mesh.getMaxIndices() < this.indices.size) {
            throw new GdxRuntimeException("Mesh can't hold enough indices: " + mesh.getMaxIndices() + " < " + this.indices.size);
        } else {
            mesh.setVertices(this.vertices.items, 0, this.vertices.size);
            mesh.setIndices(this.indices.items, 0, this.indices.size);
            Array.ArrayIterator<MeshPart> it = this.parts.iterator();
            while (it.hasNext()) {
                MeshPart p = it.next();
                p.mesh = mesh;
            }
            this.parts.clear();
            this.attributes = null;
            this.vertices.clear();
            this.indices.clear();
            return mesh;
        }
    }

    public Mesh end() {
        return end(new Mesh(true, this.vertices.size / this.stride, this.indices.size, this.attributes));
    }

    public void clear() {
        this.vertices.clear();
        this.indices.clear();
        this.parts.clear();
        this.vindex = 0;
        this.lastIndex = -1;
        this.istart = 0;
        this.part = null;
    }

    public int getFloatsPerVertex() {
        return this.stride;
    }

    public int getNumVertices() {
        return this.vertices.size / this.stride;
    }

    public void getVertices(float[] out, int destOffset) {
        if (this.attributes == null) {
            throw new GdxRuntimeException("Must be called in between #begin and #end");
        }
        if (destOffset < 0 || destOffset > out.length - this.vertices.size) {
            throw new GdxRuntimeException("Array too small or offset out of range");
        }
        System.arraycopy(this.vertices.items, 0, out, destOffset, this.vertices.size);
    }

    protected float[] getVertices() {
        return this.vertices.items;
    }

    public int getNumIndices() {
        return this.indices.size;
    }

    public void getIndices(short[] out, int destOffset) {
        if (this.attributes == null) {
            throw new GdxRuntimeException("Must be called in between #begin and #end");
        }
        if (destOffset < 0 || destOffset > out.length - this.indices.size) {
            throw new GdxRuntimeException("Array too small or offset out of range");
        }
        System.arraycopy(this.indices.items, 0, out, destOffset, this.indices.size);
    }

    protected short[] getIndices() {
        return this.indices.items;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public VertexAttributes getAttributes() {
        return this.attributes;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public MeshPart getMeshPart() {
        return this.part;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public int getPrimitiveType() {
        return this.primitiveType;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setColor(float r, float g, float b, float a) {
        this.color.set(r, g, b, a);
        this.hasColor = !this.color.equals(Color.WHITE);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setColor(Color color) {
        Color color2 = this.color;
        boolean z = color != null;
        this.hasColor = z;
        color2.set(!z ? Color.WHITE : color);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setUVRange(float u1, float v1, float u2, float v2) {
        this.uOffset = u1;
        this.vOffset = v1;
        this.uScale = u2 - u1;
        this.vScale = v2 - v1;
        this.hasUVTransform = (MathUtils.isZero(u1) && MathUtils.isZero(v1) && MathUtils.isEqual(u2, 1.0f) && MathUtils.isEqual(v2, 1.0f)) ? false : true;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setUVRange(TextureRegion region) {
        if (region == null) {
            this.hasUVTransform = false;
            this.vOffset = 0.0f;
            this.uOffset = 0.0f;
            this.vScale = 1.0f;
            this.uScale = 1.0f;
            return;
        }
        this.hasUVTransform = true;
        setUVRange(region.getU(), region.getV(), region.getU2(), region.getV2());
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public Matrix4 getVertexTransform(Matrix4 out) {
        return out.set(this.positionTransform);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setVertexTransform(Matrix4 transform) {
        this.vertexTransformationEnabled = transform != null;
        if (this.vertexTransformationEnabled) {
            this.positionTransform.set(transform);
            this.normalTransform.set(transform).inv().transpose();
            return;
        }
        this.positionTransform.idt();
        this.normalTransform.idt();
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public boolean isVertexTransformationEnabled() {
        return this.vertexTransformationEnabled;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void setVertexTransformationEnabled(boolean enabled) {
        this.vertexTransformationEnabled = enabled;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void ensureVertices(int numVertices) {
        this.vertices.ensureCapacity(this.stride * numVertices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void ensureIndices(int numIndices) {
        this.indices.ensureCapacity(numIndices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void ensureCapacity(int numVertices, int numIndices) {
        ensureVertices(numVertices);
        ensureIndices(numIndices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void ensureTriangleIndices(int numTriangles) {
        int i = this.primitiveType;
        if (i == 1) {
            ensureIndices(numTriangles * 6);
        } else if (i == 4 || i == 0) {
            ensureIndices(numTriangles * 3);
        } else {
            throw new GdxRuntimeException("Incorrect primtive type");
        }
    }

    @Deprecated
    public void ensureTriangles(int numVertices, int numTriangles) {
        ensureVertices(numVertices);
        ensureTriangleIndices(numTriangles);
    }

    @Deprecated
    public void ensureTriangles(int numTriangles) {
        ensureVertices(numTriangles * 3);
        ensureTriangleIndices(numTriangles);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void ensureRectangleIndices(int numRectangles) {
        int i = this.primitiveType;
        if (i == 0) {
            ensureIndices(numRectangles * 4);
        } else if (i == 1) {
            ensureIndices(numRectangles * 8);
        } else {
            ensureIndices(numRectangles * 6);
        }
    }

    @Deprecated
    public void ensureRectangles(int numVertices, int numRectangles) {
        ensureVertices(numVertices);
        ensureRectangleIndices(numRectangles);
    }

    @Deprecated
    public void ensureRectangles(int numRectangles) {
        ensureVertices(numRectangles * 4);
        ensureRectangleIndices(numRectangles);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public short lastIndex() {
        return (short) this.lastIndex;
    }

    private static final void transformPosition(float[] values, int offset, int size, Matrix4 transform) {
        if (size > 2) {
            vTmp.set(values[offset], values[offset + 1], values[offset + 2]).mul(transform);
            values[offset] = vTmp.x;
            values[offset + 1] = vTmp.y;
            values[offset + 2] = vTmp.z;
        } else if (size > 1) {
            vTmp.set(values[offset], values[offset + 1], 0.0f).mul(transform);
            values[offset] = vTmp.x;
            values[offset + 1] = vTmp.y;
        } else {
            values[offset] = vTmp.set(values[offset], 0.0f, 0.0f).mul(transform).x;
        }
    }

    private static final void transformNormal(float[] values, int offset, int size, Matrix3 transform) {
        if (size > 2) {
            vTmp.set(values[offset], values[offset + 1], values[offset + 2]).mul(transform).nor();
            values[offset] = vTmp.x;
            values[offset + 1] = vTmp.y;
            values[offset + 2] = vTmp.z;
        } else if (size > 1) {
            vTmp.set(values[offset], values[offset + 1], 0.0f).mul(transform).nor();
            values[offset] = vTmp.x;
            values[offset + 1] = vTmp.y;
        } else {
            values[offset] = vTmp.set(values[offset], 0.0f, 0.0f).mul(transform).nor().x;
        }
    }

    private final void addVertex(float[] values, int offset) {
        int o = this.vertices.size;
        this.vertices.addAll(values, offset, this.stride);
        int i = this.vindex;
        this.vindex = i + 1;
        this.lastIndex = i;
        if (this.vertexTransformationEnabled) {
            transformPosition(this.vertices.items, this.posOffset + o, this.posSize, this.positionTransform);
            if (this.norOffset >= 0) {
                transformNormal(this.vertices.items, this.norOffset + o, 3, this.normalTransform);
            }
            if (this.biNorOffset >= 0) {
                transformNormal(this.vertices.items, this.biNorOffset + o, 3, this.normalTransform);
            }
            if (this.tangentOffset >= 0) {
                transformNormal(this.vertices.items, this.tangentOffset + o, 3, this.normalTransform);
            }
        }
        float x = this.vertices.items[this.posOffset + o];
        float y = this.posSize > 1 ? this.vertices.items[this.posOffset + o + 1] : 0.0f;
        float z = this.posSize > 2 ? this.vertices.items[this.posOffset + o + 2] : 0.0f;
        this.bounds.ext(x, y, z);
        if (this.hasColor) {
            if (this.colOffset >= 0) {
                float[] fArr = this.vertices.items;
                int i2 = this.colOffset + o;
                fArr[i2] = fArr[i2] * this.color.r;
                float[] fArr2 = this.vertices.items;
                int i3 = this.colOffset + o + 1;
                fArr2[i3] = fArr2[i3] * this.color.g;
                float[] fArr3 = this.vertices.items;
                int i4 = this.colOffset + o + 2;
                fArr3[i4] = fArr3[i4] * this.color.b;
                if (this.colSize > 3) {
                    float[] fArr4 = this.vertices.items;
                    int i5 = this.colOffset + o + 3;
                    fArr4[i5] = fArr4[i5] * this.color.a;
                }
            } else if (this.cpOffset >= 0) {
                Color.abgr8888ToColor(this.tempC1, this.vertices.items[this.cpOffset + o]);
                this.vertices.items[this.cpOffset + o] = this.tempC1.mul(this.color).toFloatBits();
            }
        }
        if (this.hasUVTransform && this.uvOffset >= 0) {
            this.vertices.items[this.uvOffset + o] = this.uOffset + (this.uScale * this.vertices.items[this.uvOffset + o]);
            this.vertices.items[this.uvOffset + o + 1] = this.vOffset + (this.vScale * this.vertices.items[this.uvOffset + o + 1]);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public short vertex(Vector3 pos, Vector3 nor, Color col, Vector2 uv) {
        int i;
        if (this.vindex > 65535) {
            throw new GdxRuntimeException("Too many vertices used");
        }
        this.vertex[this.posOffset] = pos.x;
        if (this.posSize > 1) {
            this.vertex[this.posOffset + 1] = pos.y;
        }
        if (this.posSize > 2) {
            this.vertex[this.posOffset + 2] = pos.z;
        }
        if (this.norOffset >= 0) {
            if (nor == null) {
                nor = this.tmpNormal.set(pos).nor();
            }
            this.vertex[this.norOffset] = nor.x;
            this.vertex[this.norOffset + 1] = nor.y;
            this.vertex[this.norOffset + 2] = nor.z;
        }
        if (this.colOffset >= 0) {
            if (col == null) {
                col = Color.WHITE;
            }
            this.vertex[this.colOffset] = col.r;
            this.vertex[this.colOffset + 1] = col.g;
            this.vertex[this.colOffset + 2] = col.b;
            if (this.colSize > 3) {
                this.vertex[this.colOffset + 3] = col.a;
            }
        } else if (this.cpOffset > 0) {
            if (col == null) {
                col = Color.WHITE;
            }
            this.vertex[this.cpOffset] = col.toFloatBits();
        }
        if (uv != null && (i = this.uvOffset) >= 0) {
            this.vertex[i] = uv.x;
            this.vertex[this.uvOffset + 1] = uv.y;
        }
        addVertex(this.vertex, 0);
        return (short) this.lastIndex;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public short vertex(float... values) {
        int n = values.length - this.stride;
        int i = 0;
        while (i <= n) {
            addVertex(values, i);
            i += this.stride;
        }
        int i2 = this.lastIndex;
        return (short) i2;
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public short vertex(MeshPartBuilder.VertexInfo info) {
        return vertex(info.hasPosition ? info.position : null, info.hasNormal ? info.normal : null, info.hasColor ? info.color : null, info.hasUV ? info.uv : null);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value) {
        this.indices.add(value);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value1, short value2) {
        ensureIndices(2);
        this.indices.add(value1);
        this.indices.add(value2);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value1, short value2, short value3) {
        ensureIndices(3);
        this.indices.add(value1);
        this.indices.add(value2);
        this.indices.add(value3);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value1, short value2, short value3, short value4) {
        ensureIndices(4);
        this.indices.add(value1);
        this.indices.add(value2);
        this.indices.add(value3);
        this.indices.add(value4);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value1, short value2, short value3, short value4, short value5, short value6) {
        ensureIndices(6);
        this.indices.add(value1);
        this.indices.add(value2);
        this.indices.add(value3);
        this.indices.add(value4);
        this.indices.add(value5);
        this.indices.add(value6);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void index(short value1, short value2, short value3, short value4, short value5, short value6, short value7, short value8) {
        ensureIndices(8);
        this.indices.add(value1);
        this.indices.add(value2);
        this.indices.add(value3);
        this.indices.add(value4);
        this.indices.add(value5);
        this.indices.add(value6);
        this.indices.add(value7);
        this.indices.add(value8);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void line(short index1, short index2) {
        if (this.primitiveType != 1) {
            throw new GdxRuntimeException("Incorrect primitive type");
        }
        index(index1, index2);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void line(MeshPartBuilder.VertexInfo p1, MeshPartBuilder.VertexInfo p2) {
        ensureVertices(2);
        line(vertex(p1), vertex(p2));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void line(Vector3 p1, Vector3 p2) {
        line(this.vertTmp1.set(p1, null, null, null), this.vertTmp2.set(p2, null, null, null));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void line(float x1, float y1, float z1, float x2, float y2, float z2) {
        line(this.vertTmp1.set(null, null, null, null).setPos(x1, y1, z1), this.vertTmp2.set(null, null, null, null).setPos(x2, y2, z2));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void line(Vector3 p1, Color c1, Vector3 p2, Color c2) {
        line(this.vertTmp1.set(p1, null, c1, null), this.vertTmp2.set(p2, null, c2, null));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void triangle(short index1, short index2, short index3) {
        int i = this.primitiveType;
        if (i == 4 || i == 0) {
            index(index1, index2, index3);
        } else if (i == 1) {
            index(index1, index2, index2, index3, index3, index1);
        } else {
            throw new GdxRuntimeException("Incorrect primitive type");
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void triangle(MeshPartBuilder.VertexInfo p1, MeshPartBuilder.VertexInfo p2, MeshPartBuilder.VertexInfo p3) {
        ensureVertices(3);
        triangle(vertex(p1), vertex(p2), vertex(p3));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void triangle(Vector3 p1, Vector3 p2, Vector3 p3) {
        triangle(this.vertTmp1.set(p1, null, null, null), this.vertTmp2.set(p2, null, null, null), this.vertTmp3.set(p3, null, null, null));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void triangle(Vector3 p1, Color c1, Vector3 p2, Color c2, Vector3 p3, Color c3) {
        triangle(this.vertTmp1.set(p1, null, c1, null), this.vertTmp2.set(p2, null, c2, null), this.vertTmp3.set(p3, null, c3, null));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void rect(short corner00, short corner10, short corner11, short corner01) {
        int i = this.primitiveType;
        if (i == 4) {
            index(corner00, corner10, corner11, corner11, corner01, corner00);
        } else if (i == 1) {
            index(corner00, corner10, corner10, corner11, corner11, corner01, corner01, corner00);
        } else if (i == 0) {
            index(corner00, corner10, corner11, corner01);
        } else {
            throw new GdxRuntimeException("Incorrect primitive type");
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void rect(MeshPartBuilder.VertexInfo corner00, MeshPartBuilder.VertexInfo corner10, MeshPartBuilder.VertexInfo corner11, MeshPartBuilder.VertexInfo corner01) {
        ensureVertices(4);
        rect(vertex(corner00), vertex(corner10), vertex(corner11), vertex(corner01));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void rect(Vector3 corner00, Vector3 corner10, Vector3 corner11, Vector3 corner01, Vector3 normal) {
        rect(this.vertTmp1.set(corner00, normal, null, null).setUV(0.0f, 1.0f), this.vertTmp2.set(corner10, normal, null, null).setUV(1.0f, 1.0f), this.vertTmp3.set(corner11, normal, null, null).setUV(1.0f, 0.0f), this.vertTmp4.set(corner01, normal, null, null).setUV(0.0f, 0.0f));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void rect(float x00, float y00, float z00, float x10, float y10, float z10, float x11, float y11, float z11, float x01, float y01, float z01, float normalX, float normalY, float normalZ) {
        rect(this.vertTmp1.set(null, null, null, null).setPos(x00, y00, z00).setNor(normalX, normalY, normalZ).setUV(0.0f, 1.0f), this.vertTmp2.set(null, null, null, null).setPos(x10, y10, z10).setNor(normalX, normalY, normalZ).setUV(1.0f, 1.0f), this.vertTmp3.set(null, null, null, null).setPos(x11, y11, z11).setNor(normalX, normalY, normalZ).setUV(1.0f, 0.0f), this.vertTmp4.set(null, null, null, null).setPos(x01, y01, z01).setNor(normalX, normalY, normalZ).setUV(0.0f, 0.0f));
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void addMesh(Mesh mesh) {
        addMesh(mesh, 0, mesh.getNumIndices());
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void addMesh(MeshPart meshpart) {
        if (meshpart.primitiveType != this.primitiveType) {
            throw new GdxRuntimeException("Primitive type doesn't match");
        }
        addMesh(meshpart.mesh, meshpart.offset, meshpart.size);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void addMesh(Mesh mesh, int indexOffset, int numIndices) {
        if (!this.attributes.equals(mesh.getVertexAttributes())) {
            throw new GdxRuntimeException("Vertex attributes do not match");
        }
        if (numIndices <= 0) {
            return;
        }
        int numFloats = mesh.getNumVertices() * this.stride;
        tmpVertices.clear();
        tmpVertices.ensureCapacity(numFloats);
        FloatArray floatArray = tmpVertices;
        floatArray.size = numFloats;
        mesh.getVertices(floatArray.items);
        tmpIndices.clear();
        tmpIndices.ensureCapacity(numIndices);
        ShortArray shortArray = tmpIndices;
        shortArray.size = numIndices;
        mesh.getIndices(indexOffset, numIndices, shortArray.items, 0);
        addMesh(tmpVertices.items, tmpIndices.items, 0, numIndices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void addMesh(float[] vertices, short[] indices, int indexOffset, int numIndices) {
        IntIntMap intIntMap = indicesMap;
        if (intIntMap == null) {
            indicesMap = new IntIntMap(numIndices);
        } else {
            intIntMap.clear();
            indicesMap.ensureCapacity(numIndices);
        }
        ensureIndices(numIndices);
        int numVertices = vertices.length / this.stride;
        ensureVertices(numVertices < numIndices ? numVertices : numIndices);
        for (int i = 0; i < numIndices; i++) {
            int sidx = indices[indexOffset + i] & UShort.MAX_VALUE;
            int didx = indicesMap.get(sidx, -1);
            if (didx < 0) {
                addVertex(vertices, this.stride * sidx);
                IntIntMap intIntMap2 = indicesMap;
                int i2 = this.lastIndex;
                didx = i2;
                intIntMap2.put(sidx, i2);
            }
            index((short) didx);
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    public void addMesh(float[] vertices, short[] indices) {
        int offset = this.lastIndex + 1;
        int numVertices = vertices.length / this.stride;
        ensureVertices(numVertices);
        int v = 0;
        while (v < vertices.length) {
            addVertex(vertices, v);
            v += this.stride;
        }
        int v2 = indices.length;
        ensureIndices(v2);
        for (short s : indices) {
            index((short) (s + offset));
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void patch(MeshPartBuilder.VertexInfo corner00, MeshPartBuilder.VertexInfo corner10, MeshPartBuilder.VertexInfo corner11, MeshPartBuilder.VertexInfo corner01, int divisionsU, int divisionsV) {
        PatchShapeBuilder.build(this, corner00, corner10, corner11, corner01, divisionsU, divisionsV);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void patch(Vector3 corner00, Vector3 corner10, Vector3 corner11, Vector3 corner01, Vector3 normal, int divisionsU, int divisionsV) {
        PatchShapeBuilder.build(this, corner00, corner10, corner11, corner01, normal, divisionsU, divisionsV);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void patch(float x00, float y00, float z00, float x10, float y10, float z10, float x11, float y11, float z11, float x01, float y01, float z01, float normalX, float normalY, float normalZ, int divisionsU, int divisionsV) {
        PatchShapeBuilder.build(this, x00, y00, z00, x10, y10, z10, x11, y11, z11, x01, y01, z01, normalX, normalY, normalZ, divisionsU, divisionsV);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void box(MeshPartBuilder.VertexInfo corner000, MeshPartBuilder.VertexInfo corner010, MeshPartBuilder.VertexInfo corner100, MeshPartBuilder.VertexInfo corner110, MeshPartBuilder.VertexInfo corner001, MeshPartBuilder.VertexInfo corner011, MeshPartBuilder.VertexInfo corner101, MeshPartBuilder.VertexInfo corner111) {
        BoxShapeBuilder.build(this, corner000, corner010, corner100, corner110, corner001, corner011, corner101, corner111);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void box(Vector3 corner000, Vector3 corner010, Vector3 corner100, Vector3 corner110, Vector3 corner001, Vector3 corner011, Vector3 corner101, Vector3 corner111) {
        BoxShapeBuilder.build(this, corner000, corner010, corner100, corner110, corner001, corner011, corner101, corner111);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void box(Matrix4 transform) {
        BoxShapeBuilder.build(this, transform);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void box(float width, float height, float depth) {
        BoxShapeBuilder.build(this, width, height, depth);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void box(float x, float y, float z, float width, float height, float depth) {
        BoxShapeBuilder.build(this, x, y, z, width, height, depth);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        EllipseShapeBuilder.build(this, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, Vector3 center, Vector3 normal) {
        EllipseShapeBuilder.build(this, radius, divisions, center, normal);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal) {
        EllipseShapeBuilder.build(this, radius, divisions, center, normal, tangent, binormal);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ) {
        EllipseShapeBuilder.build(this, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, Vector3 center, Vector3 normal, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, radius, divisions, center, normal, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal, float angleFrom, float angleTo) {
        circle(radius, divisions, center.x, center.y, center.z, normal.x, normal.y, normal.z, tangent.x, tangent.y, tangent.z, binormal.x, binormal.y, binormal.z, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void circle(float radius, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, radius, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        EllipseShapeBuilder.build(this, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, Vector3 center, Vector3 normal) {
        EllipseShapeBuilder.build(this, width, height, divisions, center, normal);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal) {
        EllipseShapeBuilder.build(this, width, height, divisions, center, normal, tangent, binormal);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ) {
        EllipseShapeBuilder.build(this, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, Vector3 center, Vector3 normal, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, divisions, center, normal, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, Vector3 center, Vector3 normal, Vector3 tangent, Vector3 binormal, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, divisions, center, normal, tangent, binormal, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, float innerWidth, float innerHeight, int divisions, Vector3 center, Vector3 normal) {
        EllipseShapeBuilder.build(this, width, height, innerWidth, innerHeight, divisions, center, normal);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ) {
        EllipseShapeBuilder.build(this, width, height, innerWidth, innerHeight, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, innerWidth, innerHeight, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void ellipse(float width, float height, float innerWidth, float innerHeight, int divisions, float centerX, float centerY, float centerZ, float normalX, float normalY, float normalZ, float tangentX, float tangentY, float tangentZ, float binormalX, float binormalY, float binormalZ, float angleFrom, float angleTo) {
        EllipseShapeBuilder.build(this, width, height, innerWidth, innerHeight, divisions, centerX, centerY, centerZ, normalX, normalY, normalZ, tangentX, tangentY, tangentZ, binormalX, binormalY, binormalZ, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void cylinder(float width, float height, float depth, int divisions) {
        CylinderShapeBuilder.build(this, width, height, depth, divisions);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void cylinder(float width, float height, float depth, int divisions, float angleFrom, float angleTo) {
        CylinderShapeBuilder.build(this, width, height, depth, divisions, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void cylinder(float width, float height, float depth, int divisions, float angleFrom, float angleTo, boolean close) {
        CylinderShapeBuilder.build(this, width, height, depth, divisions, angleFrom, angleTo, close);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void cone(float width, float height, float depth, int divisions) {
        cone(width, height, depth, divisions, 0.0f, 360.0f);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void cone(float width, float height, float depth, int divisions, float angleFrom, float angleTo) {
        ConeShapeBuilder.build(this, width, height, depth, divisions, angleFrom, angleTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void sphere(float width, float height, float depth, int divisionsU, int divisionsV) {
        SphereShapeBuilder.build(this, width, height, depth, divisionsU, divisionsV);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void sphere(Matrix4 transform, float width, float height, float depth, int divisionsU, int divisionsV) {
        SphereShapeBuilder.build(this, transform, width, height, depth, divisionsU, divisionsV);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void sphere(float width, float height, float depth, int divisionsU, int divisionsV, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        SphereShapeBuilder.build(this, width, height, depth, divisionsU, divisionsV, angleUFrom, angleUTo, angleVFrom, angleVTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void sphere(Matrix4 transform, float width, float height, float depth, int divisionsU, int divisionsV, float angleUFrom, float angleUTo, float angleVFrom, float angleVTo) {
        SphereShapeBuilder.build(this, transform, width, height, depth, divisionsU, divisionsV, angleUFrom, angleUTo, angleVFrom, angleVTo);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void capsule(float radius, float height, int divisions) {
        CapsuleShapeBuilder.build(this, radius, height, divisions);
    }

    @Override // com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder
    @Deprecated
    public void arrow(float x1, float y1, float z1, float x2, float y2, float z2, float capLength, float stemThickness, int divisions) {
        ArrowShapeBuilder.build(this, x1, y1, z1, x2, y2, z2, capLength, stemThickness, divisions);
    }
}