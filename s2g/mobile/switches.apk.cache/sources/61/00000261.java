package com.badlogic.gdx.graphics.g3d.utils.shapebuilders;

import com.badlogic.gdx.graphics.Color;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.g3d.Renderable;
import com.badlogic.gdx.graphics.g3d.RenderableProvider;
import com.badlogic.gdx.graphics.g3d.utils.MeshPartBuilder;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.Array;
import com.badlogic.gdx.utils.FlushablePool;
import kotlin.jvm.internal.ShortCompanionObject;
import s2g.project.game.BuildConfig;

/* loaded from: classes.dex */
public class RenderableShapeBuilder extends BaseShapeBuilder {
    private static final int FLOAT_BYTES = 4;
    private static short[] indices;
    private static float[] vertices;
    private static final RenderablePool renderablesPool = new RenderablePool();
    private static final Array<Renderable> renderables = new Array<>();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class RenderablePool extends FlushablePool<Renderable> {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.badlogic.gdx.utils.Pool
        public Renderable newObject() {
            return new Renderable();
        }

        @Override // com.badlogic.gdx.utils.FlushablePool, com.badlogic.gdx.utils.Pool
        public Renderable obtain() {
            Renderable renderable = (Renderable) super.obtain();
            renderable.environment = null;
            renderable.material = null;
            renderable.meshPart.set(BuildConfig.FLAVOR, null, 0, 0, 0);
            renderable.shader = null;
            renderable.userData = null;
            return renderable;
        }
    }

    public static void buildNormals(MeshPartBuilder builder, RenderableProvider renderableProvider, float vectorSize) {
        buildNormals(builder, renderableProvider, vectorSize, tmpColor0.set(0.0f, 0.0f, 1.0f, 1.0f), tmpColor1.set(1.0f, 0.0f, 0.0f, 1.0f), tmpColor2.set(0.0f, 1.0f, 0.0f, 1.0f));
    }

    public static void buildNormals(MeshPartBuilder builder, RenderableProvider renderableProvider, float vectorSize, Color normalColor, Color tangentColor, Color binormalColor) {
        renderableProvider.getRenderables(renderables, renderablesPool);
        Array.ArrayIterator<Renderable> it = renderables.iterator();
        while (it.hasNext()) {
            Renderable renderable = it.next();
            buildNormals(builder, renderable, vectorSize, normalColor, tangentColor, binormalColor);
        }
        renderablesPool.flush();
        renderables.clear();
    }

    public static void buildNormals(MeshPartBuilder builder, Renderable renderable, float vectorSize, Color normalColor, Color tangentColor, Color binormalColor) {
        int verticesOffset;
        int verticesQuantity;
        Renderable renderable2 = renderable;
        Mesh mesh = renderable2.meshPart.mesh;
        int positionOffset = -1;
        if (mesh.getVertexAttribute(1) != null) {
            positionOffset = mesh.getVertexAttribute(1).offset / 4;
        }
        int normalOffset = -1;
        if (mesh.getVertexAttribute(8) != null) {
            normalOffset = mesh.getVertexAttribute(8).offset / 4;
        }
        int tangentOffset = -1;
        if (mesh.getVertexAttribute(128) != null) {
            tangentOffset = mesh.getVertexAttribute(128).offset / 4;
        }
        int binormalOffset = -1;
        if (mesh.getVertexAttribute(256) != null) {
            binormalOffset = mesh.getVertexAttribute(256).offset / 4;
        }
        int attributesSize = mesh.getVertexSize() / 4;
        if (mesh.getNumIndices() > 0) {
            ensureIndicesCapacity(mesh.getNumIndices());
            mesh.getIndices(renderable2.meshPart.offset, renderable2.meshPart.size, indices, 0);
            short minVertice = minVerticeInIndices();
            short maxVertice = maxVerticeInIndices();
            verticesOffset = minVertice;
            verticesQuantity = maxVertice - minVertice;
        } else {
            verticesOffset = renderable2.meshPart.offset;
            verticesQuantity = renderable2.meshPart.size;
        }
        ensureVerticesCapacity(verticesQuantity * attributesSize);
        mesh.getVertices(verticesOffset * attributesSize, verticesQuantity * attributesSize, vertices, 0);
        int i = verticesOffset;
        while (i < verticesQuantity) {
            int id = i * attributesSize;
            Vector3 vector3 = tmpV0;
            float[] fArr = vertices;
            Mesh mesh2 = mesh;
            vector3.set(fArr[id + positionOffset], fArr[id + positionOffset + 1], fArr[id + positionOffset + 2]);
            if (normalOffset != -1) {
                Vector3 vector32 = tmpV1;
                float[] fArr2 = vertices;
                vector32.set(fArr2[id + normalOffset], fArr2[id + normalOffset + 1], fArr2[id + normalOffset + 2]);
                tmpV2.set(tmpV0).add(tmpV1.scl(vectorSize));
            }
            if (tangentOffset != -1) {
                Vector3 vector33 = tmpV3;
                float[] fArr3 = vertices;
                vector33.set(fArr3[id + tangentOffset], fArr3[id + tangentOffset + 1], fArr3[id + tangentOffset + 2]);
                tmpV4.set(tmpV0).add(tmpV3.scl(vectorSize));
            }
            if (binormalOffset != -1) {
                Vector3 vector34 = tmpV5;
                float[] fArr4 = vertices;
                vector34.set(fArr4[id + binormalOffset], fArr4[id + binormalOffset + 1], fArr4[id + binormalOffset + 2]);
                tmpV6.set(tmpV0).add(tmpV5.scl(vectorSize));
            }
            tmpV0.mul(renderable2.worldTransform);
            tmpV2.mul(renderable2.worldTransform);
            tmpV4.mul(renderable2.worldTransform);
            tmpV6.mul(renderable2.worldTransform);
            if (normalOffset != -1) {
                builder.setColor(normalColor);
                builder.line(tmpV0, tmpV2);
            }
            if (tangentOffset != -1) {
                builder.setColor(tangentColor);
                builder.line(tmpV0, tmpV4);
            }
            if (binormalOffset != -1) {
                builder.setColor(binormalColor);
                builder.line(tmpV0, tmpV6);
            }
            i++;
            renderable2 = renderable;
            mesh = mesh2;
        }
    }

    private static void ensureVerticesCapacity(int capacity) {
        float[] fArr = vertices;
        if (fArr == null || fArr.length < capacity) {
            vertices = new float[capacity];
        }
    }

    private static void ensureIndicesCapacity(int capacity) {
        short[] sArr = indices;
        if (sArr == null || sArr.length < capacity) {
            indices = new short[capacity];
        }
    }

    private static short minVerticeInIndices() {
        short min = ShortCompanionObject.MAX_VALUE;
        int i = 0;
        while (true) {
            short[] sArr = indices;
            if (i < sArr.length) {
                if (sArr[i] < min) {
                    min = sArr[i];
                }
                i++;
            } else {
                return min;
            }
        }
    }

    private static short maxVerticeInIndices() {
        short max = ShortCompanionObject.MIN_VALUE;
        int i = 0;
        while (true) {
            short[] sArr = indices;
            if (i < sArr.length) {
                if (sArr[i] > max) {
                    max = sArr[i];
                }
                i++;
            } else {
                return max;
            }
        }
    }
}