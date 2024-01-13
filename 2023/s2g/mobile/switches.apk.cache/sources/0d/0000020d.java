package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.g3d.Model;
import com.badlogic.gdx.graphics.g3d.particles.values.MeshSpawnShapeValue;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;

/* loaded from: classes.dex */
public final class UnweightedMeshSpawnShapeValue extends MeshSpawnShapeValue {
    private short[] indices;
    private int positionOffset;
    private int triangleCount;
    private int vertexCount;
    private int vertexSize;
    private float[] vertices;

    public UnweightedMeshSpawnShapeValue(UnweightedMeshSpawnShapeValue value) {
        super(value);
        load(value);
    }

    public UnweightedMeshSpawnShapeValue() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.MeshSpawnShapeValue
    public void setMesh(Mesh mesh, Model model) {
        super.setMesh(mesh, model);
        this.vertexSize = mesh.getVertexSize() / 4;
        this.positionOffset = mesh.getVertexAttribute(1).offset / 4;
        int indicesCount = mesh.getNumIndices();
        if (indicesCount > 0) {
            this.indices = new short[indicesCount];
            mesh.getIndices(this.indices);
            this.triangleCount = this.indices.length / 3;
        } else {
            this.indices = null;
        }
        this.vertexCount = mesh.getNumVertices();
        this.vertices = new float[this.vertexCount * this.vertexSize];
        mesh.getVertices(this.vertices);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public void spawnAux(Vector3 vector, float percent) {
        if (this.indices == null) {
            int random = MathUtils.random(this.vertexCount - 3);
            int i = this.vertexSize;
            int p1Offset = this.positionOffset + (random * i);
            int p2Offset = p1Offset + i;
            int p3Offset = i + p2Offset;
            float[] fArr = this.vertices;
            float x1 = fArr[p1Offset];
            float y1 = fArr[p1Offset + 1];
            float z1 = fArr[p1Offset + 2];
            float x2 = fArr[p2Offset];
            float y2 = fArr[p2Offset + 1];
            float z2 = fArr[p2Offset + 2];
            float x3 = fArr[p3Offset];
            float y3 = fArr[p3Offset + 1];
            float z3 = fArr[p3Offset + 2];
            MeshSpawnShapeValue.Triangle.pick(x1, y1, z1, x2, y2, z2, x3, y3, z3, vector);
            return;
        }
        int triangleIndex = MathUtils.random(this.triangleCount - 1) * 3;
        short[] sArr = this.indices;
        short s = sArr[triangleIndex];
        int i2 = this.vertexSize;
        int i3 = this.positionOffset;
        int p1Offset2 = (s * i2) + i3;
        int p2Offset2 = (sArr[triangleIndex + 1] * i2) + i3;
        int p3Offset2 = (sArr[triangleIndex + 2] * i2) + i3;
        float[] fArr2 = this.vertices;
        float x12 = fArr2[p1Offset2];
        float y12 = fArr2[p1Offset2 + 1];
        float z12 = fArr2[p1Offset2 + 2];
        float x22 = fArr2[p2Offset2];
        float y22 = fArr2[p2Offset2 + 1];
        float z22 = fArr2[p2Offset2 + 2];
        float x32 = fArr2[p3Offset2];
        float y32 = fArr2[p3Offset2 + 1];
        float z32 = fArr2[p3Offset2 + 2];
        MeshSpawnShapeValue.Triangle.pick(x12, y12, z12, x22, y22, z22, x32, y32, z32, vector);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue
    public SpawnShapeValue copy() {
        return new UnweightedMeshSpawnShapeValue(this);
    }
}