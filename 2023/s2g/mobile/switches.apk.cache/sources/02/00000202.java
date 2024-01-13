package com.badlogic.gdx.graphics.g3d.particles.values;

import com.badlogic.gdx.assets.AssetDescriptor;
import com.badlogic.gdx.assets.AssetManager;
import com.badlogic.gdx.graphics.Mesh;
import com.badlogic.gdx.graphics.g3d.Model;
import com.badlogic.gdx.graphics.g3d.particles.ResourceData;
import com.badlogic.gdx.math.MathUtils;
import com.badlogic.gdx.math.Vector3;
import com.badlogic.gdx.utils.GdxRuntimeException;

/* loaded from: classes.dex */
public abstract class MeshSpawnShapeValue extends SpawnShapeValue {
    protected Mesh mesh;
    protected Model model;

    /* loaded from: classes.dex */
    public static class Triangle {
        float x1;
        float x2;
        float x3;
        float y1;
        float y2;
        float y3;
        float z1;
        float z2;
        float z3;

        public Triangle(float x1, float y1, float z1, float x2, float y2, float z2, float x3, float y3, float z3) {
            this.x1 = x1;
            this.y1 = y1;
            this.z1 = z1;
            this.x2 = x2;
            this.y2 = y2;
            this.z2 = z2;
            this.x3 = x3;
            this.y3 = y3;
            this.z3 = z3;
        }

        public static Vector3 pick(float x1, float y1, float z1, float x2, float y2, float z2, float x3, float y3, float z3, Vector3 vector) {
            float a = MathUtils.random();
            float b = MathUtils.random();
            return vector.set(((x2 - x1) * a) + x1 + ((x3 - x1) * b), ((y2 - y1) * a) + y1 + ((y3 - y1) * b), ((z2 - z1) * a) + z1 + ((z3 - z1) * b));
        }

        public Vector3 pick(Vector3 vector) {
            float a = MathUtils.random();
            float b = MathUtils.random();
            float f = this.x1;
            float f2 = this.y1;
            float f3 = this.z1;
            return vector.set(((this.x2 - f) * a) + f + ((this.x3 - f) * b), ((this.y2 - f2) * a) + f2 + ((this.y3 - f2) * b), ((this.z2 - f3) * a) + f3 + ((this.z3 - f3) * b));
        }
    }

    public MeshSpawnShapeValue(MeshSpawnShapeValue value) {
        super(value);
    }

    public MeshSpawnShapeValue() {
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.values.ParticleValue
    public void load(ParticleValue value) {
        super.load(value);
        MeshSpawnShapeValue spawnShapeValue = (MeshSpawnShapeValue) value;
        setMesh(spawnShapeValue.mesh, spawnShapeValue.model);
    }

    public void setMesh(Mesh mesh, Model model) {
        if (mesh.getVertexAttribute(1) == null) {
            throw new GdxRuntimeException("Mesh vertices must have Usage.Position");
        }
        this.model = model;
        this.mesh = mesh;
    }

    public void setMesh(Mesh mesh) {
        setMesh(mesh, null);
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void save(AssetManager manager, ResourceData data) {
        if (this.model != null) {
            ResourceData.SaveData saveData = data.createSaveData();
            saveData.saveAsset(manager.getAssetFileName(this.model), Model.class);
            saveData.save("index", Integer.valueOf(this.model.meshes.indexOf(this.mesh, true)));
        }
    }

    @Override // com.badlogic.gdx.graphics.g3d.particles.values.SpawnShapeValue, com.badlogic.gdx.graphics.g3d.particles.ResourceData.Configurable
    public void load(AssetManager manager, ResourceData data) {
        ResourceData.SaveData saveData = data.getSaveData();
        AssetDescriptor descriptor = saveData.loadAsset();
        if (descriptor != null) {
            Model model = (Model) manager.get(descriptor);
            setMesh(model.meshes.get(((Integer) saveData.load("index")).intValue()), model);
        }
    }
}